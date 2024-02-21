package gcp_pods

import (
	"context"
	mock_client "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	mock_gcp "github.com/otterize/credentials-operator/src/mocks/gcp"
	"github.com/otterize/credentials-operator/src/shared/testutils"
	"github.com/samber/lo"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
)

const (
	testPodName            = "pod"
	testNamespace          = "namespace"
	testServiceAccountName = "serviceaccount"
	testPodUID             = "pod-uid"
)

type TestGcpPodsControllerSuite struct {
	suite.Suite
	controller   *gomock.Controller
	client       *mock_client.MockClient
	mockGCPAgent *mock_gcp.MockGCPServiceAccountManager
	reconciler   *Reconciler
}

func (s *TestGcpPodsControllerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.mockGCPAgent = mock_gcp.NewMockGCPServiceAccountManager(s.controller)
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

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestGcpPodsControllerSuite))
}
