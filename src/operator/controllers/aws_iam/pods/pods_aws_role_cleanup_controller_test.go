package pods

import (
	"context"
	"errors"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	mock_client "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
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

type TestPodsRoleCleanupControllerSuite struct {
	suite.Suite
	controller *gomock.Controller
	client     *mock_client.MockClient
	reconciler *PodAWSRoleCleanupReconciler
}

func (s *TestPodsRoleCleanupControllerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.reconciler = NewPodAWSRoleCleanupReconciler(s.client)
}

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_PodNotTerminatingNotAffected() {
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

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_PodTerminatingWithNoFinalizerIsNotAffected() {
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

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_LastPodTerminatingButDifferentPodUIDDoesNotLabelServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.AWSRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{podServiceAccountIndexField: serviceAccount.Name},
		gomock.Any(),
	).DoAndReturn(
		func(arg0 context.Context, arg1 *corev1.PodList, arg2 ...client.ListOption) error {
			podList := corev1.PodList{Items: []corev1.Pod{pod}}
			podList.Items[0].UID += "somestring"

			podList.DeepCopyInto(arg1)
			return nil
		},
	)

	// should not update serviceaccount because UID was different
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.AWSRoleFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_LastPodTerminatingWithFinalizerLabelsServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.AWSRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{podServiceAccountIndexField: serviceAccount.Name},
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
	updatedServiceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasNoPodsValue}

	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any())

	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.AWSRoleFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_NonLastPodTerminatingDoesNotLabelServiceAccountAndRemovesFinalizer() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.AWSRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{podServiceAccountIndexField: serviceAccount.Name},
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

	// should not update serviceaccount because it's not the last pod
	updatedPod := pod.DeepCopy()
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.AWSRoleFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_LastPodTerminatingWithFinalizerServiceAccountGoneAndRemovesFinalizerAnyway() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.AWSRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{podServiceAccountIndexField: serviceAccount.Name},
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
	s.Require().True(controllerutil.RemoveFinalizer(updatedPod, metadata.AWSRoleFinalizer))

	s.client.EXPECT().Patch(gomock.Any(), updatedPod, gomock.Any())

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func (s *TestPodsRoleCleanupControllerSuite) TestPodsRoleCleanupController_LastPodTerminatingWithFinalizerLabelsServiceAccountButIsConflictSoRequeues() {
	req := testutils.GetTestRequestSchema()

	serviceAccount := testutils.GetTestServiceSchema()
	serviceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasPodsValue}

	pod := testutils.GetTestPodSchema()
	pod.DeletionTimestamp = lo.ToPtr(metav1.Now())
	pod.Finalizers = []string{metadata.AWSRoleFinalizer}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&pod)).DoAndReturn(
		func(arg0 context.Context, arg1 types.NamespacedName, arg2 *corev1.Pod, arg3 ...client.GetOption) error {
			pod.DeepCopyInto(arg2)
			return nil
		},
	)

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.PodList{}),
		client.MatchingFields{podServiceAccountIndexField: serviceAccount.Name},
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
	updatedServiceAccount.Labels = map[string]string{metadata.OtterizeServiceAccountLabel: metadata.OtterizeServiceAccountHasNoPodsValue}

	s.client.EXPECT().Patch(gomock.Any(), updatedServiceAccount, gomock.Any()).Return(k8serrors.NewConflict(schema.GroupResource{}, serviceAccount.Name, errors.New("conflict")))

	res, err := s.reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Equal(reconcile.Result{Requeue: true}, res)
}

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestPodsRoleCleanupControllerSuite))
}
