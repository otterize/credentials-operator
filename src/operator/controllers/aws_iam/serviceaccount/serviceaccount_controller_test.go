package serviceaccount

import (
	"context"
	"github.com/otterize/credentials-operator/src/controllers/aws_iam/serviceaccount/mocks"
	mock_client "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"testing"
)

type TestServiceAccountSuite struct {
	suite.Suite
	controller *gomock.Controller
	client     *mock_client.MockClient
	mockAWS    *mock_serviceaccount.MockAWSRolePolicyManager
}

func (s *TestServiceAccountSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.mockAWS = mock_serviceaccount.NewMockAWSRolePolicyManager(s.controller)
}

func (s *TestServiceAccountSuite) TestServiceAccountReconciler_Reconcile() {
	reconciler := NewServiceAccountReconciler(s.client, s.mockAWS)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "namespace", Name: "serviceaccount"},
	}

	serviceAccount := corev1.ServiceAccount{}

	s.client.EXPECT().Get(gomock.Any(), req.NamespacedName, gomock.AssignableToTypeOf(&serviceAccount))

	res, err := reconciler.Reconcile(context.Background(), req)
	s.Require().NoError(err)
	s.Require().Empty(res)
}

func TestRunServiceAccountControllerSuite(t *testing.T) {
	suite.Run(t, new(TestServiceAccountSuite))
}
