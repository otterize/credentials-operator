package gcp_service_accounts

import (
	"context"
	"errors"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	mockclient "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	mockgcp "github.com/otterize/credentials-operator/src/mocks/gcp"
	"github.com/otterize/credentials-operator/src/shared/testutils"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"testing"
)

type TestGcpServiceAccountsControllerSuite struct {
	suite.Suite
	controller   *gomock.Controller
	client       *mockclient.MockClient
	mockGCPAgent *mockgcp.MockGCPServiceAccountManager
	reconciler   *Reconciler
}

func (s *TestGcpServiceAccountsControllerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mockclient.NewMockClient(s.controller)
	s.mockGCPAgent = mockgcp.NewMockGCPServiceAccountManager(s.controller)
	s.reconciler = NewReconciler(s.client, s.mockGCPAgent)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountWithoutLabelsNotAffected() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()

	saNamespacedName := types.NamespacedName{Namespace: serviceAccount.Namespace, Name: serviceAccount.Name}
	s.client.EXPECT().Get(gomock.Any(), saNamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountHasGSAAndHasPodsNotAffected() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Annotations = map[string]string{metadata.GCPWorkloadIdentityAnnotation: "has-gsa"}
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}
	serviceAccount.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountNoGSANamespaceAnnotationFailCausesRequeues() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Annotations = map[string]string{metadata.GCPWorkloadIdentityAnnotation: metadata.GCPWorkloadIdentityNotSet}
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	// Should tag the pod with a finalizer
	updatedSAFinalizer := serviceAccount.DeepCopy()
	s.Require().True(controllerutil.AddFinalizer(updatedSAFinalizer, metadata.GCPSAFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedSAFinalizer, gomock.Any())

	// Annotating the namespace fails
	s.mockGCPAgent.EXPECT().AnnotateGKENamespace(context.Background(), serviceAccount.Namespace).Return(true, nil)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Equal(reconcile.Result{Requeue: true}, res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountNoGSACreatesAllDependencies() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Annotations = map[string]string{metadata.GCPWorkloadIdentityAnnotation: metadata.GCPWorkloadIdentityNotSet}
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	// Should tag the pod with a finalizer
	updatedSAFinalizer := serviceAccount.DeepCopy()
	s.Require().True(controllerutil.AddFinalizer(updatedSAFinalizer, metadata.GCPSAFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedSAFinalizer, gomock.Any())

	// Should annotate namespace
	s.mockGCPAgent.EXPECT().AnnotateGKENamespace(context.Background(), serviceAccount.Namespace).Return(false, nil)

	// Should create and connect GSA
	s.mockGCPAgent.EXPECT().CreateAndConnectGSA(context.Background(), serviceAccount.Namespace, serviceAccount.Name).Return(nil)

	// Should annotate the service account with the GCP IAM role
	gsaName := "new-gsa-name"
	updatedSA := updatedSAFinalizer.DeepCopy()
	s.mockGCPAgent.EXPECT().GetGSAFullName(serviceAccount.Namespace, serviceAccount.Name).Return(gsaName)
	updatedSA.Annotations[metadata.GCPWorkloadIdentityAnnotation] = gsaName
	s.client.EXPECT().Patch(gomock.Any(), updatedSA, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountTerminatingWithNoLabelIsNotAffected() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.DeletionTimestamp = lo.ToPtr(metav1.Now())

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountTerminatingWithLabelAndFinalizerRemovesRoleTagsAndFinalizer() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.DeletionTimestamp = lo.ToPtr(metav1.Now())
	serviceAccount.Annotations = map[string]string{metadata.GCPWorkloadIdentityAnnotation: "test"}
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}
	serviceAccount.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockGCPAgent.EXPECT().DeleteGSA(context.Background(), serviceAccount.Namespace, serviceAccount.Name).Return(nil)

	updatedServiceAccount := serviceAccount.DeepCopy()
	updatedServiceAccount.Labels = map[string]string{}
	updatedServiceAccount.Annotations = map[string]string{}
	s.Require().True(controllerutil.RemoveFinalizer(updatedServiceAccount, metadata.GCPSAFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpServiceAccountsControllerSuite) TestServiceAccountTerminatingButRoleDeletionFailsSoDoesntRemoveFinalizer() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.DeletionTimestamp = lo.ToPtr(metav1.Now())
	serviceAccount.Annotations = map[string]string{metadata.GCPWorkloadIdentityAnnotation: "test"}
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}
	serviceAccount.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockGCPAgent.EXPECT().DeleteGSA(context.Background(), serviceAccount.Namespace, serviceAccount.Name).Return(errors.New("role deletion failed"))

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().ErrorContains(err, "role deletion failed")
	s.Require().Empty(res)
}

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestGcpServiceAccountsControllerSuite))
}
