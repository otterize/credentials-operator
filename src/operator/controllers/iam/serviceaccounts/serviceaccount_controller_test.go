package serviceaccount

import (
	"context"
	"github.com/otterize/credentials-operator/src/controllers/iam"
	mock_iam "github.com/otterize/credentials-operator/src/controllers/iam/mocks"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	mock_client "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	"github.com/otterize/credentials-operator/src/shared/testutils"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"testing"
)

type TestServiceAccountSuite struct {
	suite.Suite
	controller *gomock.Controller
	client     *mock_client.MockClient
	mockIAM    *mock_iam.MockIAMCredentialsAgent
	reconciler *ServiceAccountReconciler
}

func (s *TestServiceAccountSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.mockIAM = mock_iam.NewMockIAMCredentialsAgent(s.controller)
	s.reconciler = NewServiceAccountReconciler(s.client, []iam.IAMCredentialsAgent{s.mockIAM})
}

const (
	testPodName            = "pod"
	testNamespace          = "namespace"
	testServiceAccountName = "serviceaccount"
	testPodUID             = "pod-uid"
	testRoleARN            = "role-arn"
	testRoleName           = "role-name"
)

// Tests:
// 1. SA not being deleted and is not modified.
// 2. SA deleted but no finalizer and is not modified.
// 3. SA with finalizer causes role delete.
// 4. SA with finalizer causes deletion to role but role is 404 so sa is terminated successfully.
// 5. SA with finalizer causes update to role but role update returns error so is retried, and terminates successfully on second attempt.

func (s *TestServiceAccountSuite) TestServiceAccountSuite_ServiceAccountNotTerminatingAndHasPodsNotAffected() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Annotations = map[string]string{metadata.ServiceAccountAWSRoleARNAnnotation: testRoleARN}
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}
	serviceAccount.Finalizers = []string{metadata.IAMRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockIAM.EXPECT().ReconcileServiceIAMRole(gomock.Any(), gomock.AssignableToTypeOf(&serviceAccount)).Return(false, false, nil)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestServiceAccountSuite) TestServiceAccountSuite_ServiceAccountTerminatingWithNoLabelIsNotAffected() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.DeletionTimestamp = lo.ToPtr(metav1.Now())
	serviceAccount.Finalizers = []string{metadata.IAMRoleFinalizer}
	serviceAccount.Annotations = map[string]string{metadata.ServiceAccountAWSRoleARNAnnotation: testRoleARN}

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

func (s *TestServiceAccountSuite) TestServiceAccountSuite_ServiceAccountTerminatingWithLabelAndFinalizerRemovesRoleAndFinalizer() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              testServiceAccountName,
			Namespace:         testNamespace,
			Annotations:       map[string]string{metadata.ServiceAccountAWSRoleARNAnnotation: testRoleARN},
			Labels:            map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue},
			DeletionTimestamp: lo.ToPtr(metav1.Now()),
			Finalizers:        []string{metadata.IAMRoleFinalizer},
		},
	}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockIAM.EXPECT().DeleteServiceIAMRole(context.Background(), testNamespace, testServiceAccountName).Return(nil)

	updatedServiceAccount := serviceAccount.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedServiceAccount, metadata.IAMRoleFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestServiceAccountSuite) TestServiceAccountSuite_ServiceAccountServiceAccountLabeledNoPodsDeletesRoleAndDoesntRemoveFinalizer() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testServiceAccountName,
			Namespace:   testNamespace,
			Annotations: map[string]string{metadata.ServiceAccountAWSRoleARNAnnotation: testRoleARN},
			Labels:      map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasNoPodsValue},
			Finalizers:  []string{metadata.IAMRoleFinalizer},
		},
	}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockIAM.EXPECT().DeleteServiceIAMRole(context.Background(), testNamespace, testServiceAccountName).Return(nil)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestServiceAccountSuite) TestServiceAccountSuite_ServiceAccountServiceAccountTerminatingButRoleDeletionFailsSoDoesntRemoveFinalizer() {
	req := testutils.GetTestServiceRequestSchema()

	serviceAccount := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:              testServiceAccountName,
			Namespace:         testNamespace,
			Annotations:       map[string]string{metadata.ServiceAccountAWSRoleARNAnnotation: testRoleARN},
			Labels:            map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue},
			DeletionTimestamp: lo.ToPtr(metav1.Now()),
			Finalizers:        []string{metadata.IAMRoleFinalizer},
		},
	}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	s.mockIAM.EXPECT().DeleteServiceIAMRole(context.Background(), testNamespace, testServiceAccountName).Return(errors.New("role deletion failed"))

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().ErrorContains(err, "role deletion failed")
	s.Require().Empty(res)
}

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestServiceAccountSuite))
}
