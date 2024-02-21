package gcp_pods

import (
	"context"
	"errors"
	"github.com/GoogleCloudPlatform/k8s-config-connector/operator/pkg/k8s"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	mockclient "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	mockgcp "github.com/otterize/credentials-operator/src/mocks/gcp"
	"github.com/otterize/credentials-operator/src/shared/apiutils"
	"github.com/otterize/credentials-operator/src/shared/testutils"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"testing"
)

type TestGcpPodsControllerSuite struct {
	suite.Suite
	controller   *gomock.Controller
	client       *mockclient.MockClient
	mockGCPAgent *mockgcp.MockGCPServiceAccountManager
	reconciler   *Reconciler
}

func (s *TestGcpPodsControllerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mockclient.NewMockClient(s.controller)
	s.mockGCPAgent = mockgcp.NewMockGCPServiceAccountManager(s.controller)
	s.reconciler = NewReconciler(s.client, s.mockGCPAgent)
}

func (s *TestGcpPodsControllerSuite) TestPodWithoutLabelsNotAffected() {
	req := testutils.GetTestRequestSchema()
	pod := testutils.GetTestPodSchema()

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLabeledPodTriggersSettingServiceAccountLabel() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()

	pod := testutils.GetTestPodSchema()
	pod.Labels = map[string]string{metadata.CreateGCPRoleLabel: "true"}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	saNamespacedName := types.NamespacedName{Namespace: serviceAccount.Namespace, Name: serviceAccount.Name}
	s.client.EXPECT().Get(gomock.Any(), saNamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	// Should tag the pod with a finalizer
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.AddFinalizer(updatedPod, metadata.GCPSAFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	// Should tag the service account with the required labels and annotations
	updatedServiceAccount := serviceAccount.DeepCopy()
	updatedServiceAccount.Annotations = map[string]string{k8s.WorkloadIdentityAnnotation: metadata.GCPWorkloadIdentityNotSet}
	updatedServiceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}
	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLabeledPodIsNotReTaggingServiceAccount() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.Labels = map[string]string{metadata.CreateGCPRoleLabel: "true"}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	saNamespacedName := types.NamespacedName{Namespace: serviceAccount.Namespace, Name: serviceAccount.Name}
	s.client.EXPECT().Get(gomock.Any(), saNamespacedName, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	// Should tag the pod with a finalizer
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.AddFinalizer(updatedPod, metadata.GCPSAFinalizer))
	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestPodTerminatingWithNoFinalizerIsNotAffected() {
	req := testutils.GetTestRequestSchema()

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLastPodTerminatingButDifferentPodUIDDoesNotLabelServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{apiutils.PodServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			podList := corev1.PodList{Items: []corev1.Pod{pod}}
			podList.Items[0].UID += "somestring"

			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	// should not update service account because UID was different
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.GCPSAFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLastPodTerminatingWithFinalizerLabelsServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{apiutils.PodServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			podList := corev1.PodList{Items: []corev1.Pod{pod}}

			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	s.client.EXPECT().Get(gomock.Any(), types.NamespacedName{
		Namespace: serviceAccount.Namespace,
		Name:      serviceAccount.Name,
	}, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	updatedServiceAccount := serviceAccount.DeepCopy()
	updatedServiceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasNoPodsValue}

	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any())

	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.GCPSAFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestNonLastPodTerminatingDoesNotLabelServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{apiutils.PodServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			pod2 := testutils.GetTestPodSchema()
			pod2.UID += "2"
			pod2.Name += "2"

			podList := corev1.PodList{Items: []corev1.Pod{pod, pod2}}
			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	// should not update service account because it's not the last pod
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.GCPSAFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLastPodTerminatingWithFinalizerServiceAccountGoneAndRemovesFinalizerAnyway() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{apiutils.PodServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			podList := corev1.PodList{Items: []corev1.Pod{pod}}
			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	s.client.EXPECT().Get(gomock.Any(), types.NamespacedName{
		Namespace: serviceAccount.Namespace,
		Name:      serviceAccount.Name,
	}, gomock.AssignableToTypeOf(&serviceAccount)).Return(k8serrors.NewNotFound(schema.GroupResource{}, serviceAccount.Name))

	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.GCPSAFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestGcpPodsControllerSuite) TestLastPodTerminatingWithFinalizerLabelsServiceAccountButIsConflictSoRequeues() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.GCPSAFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{apiutils.PodServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			podList := corev1.PodList{Items: []corev1.Pod{pod}}

			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	s.client.EXPECT().Get(gomock.Any(), types.NamespacedName{
		Namespace: serviceAccount.Namespace,
		Name:      serviceAccount.Name,
	}, gomock.AssignableToTypeOf(&serviceAccount)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.ServiceAccount, arg3 ...client.GetOption) error {
			serviceAccount.DeepCopyInto(arg2)
			return nil
		},
	)

	updatedServiceAccount := serviceAccount.DeepCopy()
	updatedServiceAccount.Labels = map[string]string{metadata.OtterizeGCPServiceAccountLabel: metadata.OtterizeServiceAccountHasNoPodsValue}

	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any()).Return(k8serrors.NewConflict(schema.GroupResource{}, serviceAccount.Name, errors.New("conflict")))

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Equal(reconcile.Result{Requeue: true}, res)
}

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestGcpPodsControllerSuite))
}
