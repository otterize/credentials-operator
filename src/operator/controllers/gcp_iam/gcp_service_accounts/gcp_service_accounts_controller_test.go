package gcp_service_accounts

import (
	"context"
	mockclient "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	mockgcp "github.com/otterize/credentials-operator/src/mocks/gcp"
	"github.com/otterize/credentials-operator/src/shared/testutils"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestGcpServiceAccountsControllerSuite))
}
