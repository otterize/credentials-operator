package serviceaccount

import (
	"context"
	"fmt"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	mock_client "github.com/otterize/credentials-operator/src/mocks/controller-runtime/client"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"net/http"
	"testing"
)

type serviceAccountMatcher struct {
	Name      string
	Namespace string
}

func (m *serviceAccountMatcher) String() string {
	return fmt.Sprintf("expected Name: %s Namespace: %s", m.Name, m.Namespace)
}

func (m *serviceAccountMatcher) Matches(x interface{}) bool {
	sa := x.(*v1.ServiceAccount)
	return sa.Name == m.Name && sa.Namespace == m.Namespace
}

type PodServiceAccountEnsurerSuite struct {
	suite.Suite
	controller            *gomock.Controller
	client                *mock_client.MockClient
	ServiceAccountEnsurer *Ensurer
}

func (s *PodServiceAccountEnsurerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	s.client.EXPECT().Scheme().Return(scheme).AnyTimes()
	s.ServiceAccountEnsurer = NewServiceAccountEnsurer(s.client)
}

func (s *PodServiceAccountEnsurerSuite) TestCreate() {
	serviceAccountName := "cool.name"
	annotations := map[string]string{metadata.ServiceAccountNameAnnotation: serviceAccountName}
	namespace := "namespace"
	s.client.EXPECT().Get(gomock.Any(), gomock.Eq(types.NamespacedName{Name: serviceAccountName, Namespace: namespace}), gomock.AssignableToTypeOf(&v1.ServiceAccount{})).
		Return(
			&errors.StatusError{
				ErrStatus: metav1.Status{Status: metav1.StatusFailure, Code: http.StatusNotFound, Reason: metav1.StatusReasonNotFound},
			})

	s.client.EXPECT().Create(gomock.Any(), &serviceAccountMatcher{Name: serviceAccountName, Namespace: namespace})
	err := s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: namespace, Annotations: annotations}})
	s.Require().NoError(err)

}

func (s *PodServiceAccountEnsurerSuite) TestDoesntCreateWhenFound() {
	serviceAccountName := "cool.name"
	annotations := map[string]string{metadata.ServiceAccountNameAnnotation: serviceAccountName}
	namespace := "namespace"
	s.client.EXPECT().Get(gomock.Any(), gomock.Eq(types.NamespacedName{Name: serviceAccountName, Namespace: namespace}), gomock.AssignableToTypeOf(&v1.ServiceAccount{})).
		Return(nil)

	err := s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: namespace, Annotations: annotations}})
	s.Require().NoError(err)

}

func (s *PodServiceAccountEnsurerSuite) TestDoesntCreateWhenInvalidName() {
	// Name with caps
	annotations := map[string]string{metadata.ServiceAccountNameAnnotation: "NameWithCapitalLetters"}
	err := s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: "namespace", Annotations: annotations}})
	s.Require().NoError(err)

	// Very long Name (>253)
	annotations = map[string]string{metadata.ServiceAccountNameAnnotation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	err = s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: "namespace", Annotations: annotations}})
	s.Require().NoError(err)

	// Name with /
	annotations = map[string]string{metadata.ServiceAccountNameAnnotation: "name/asd"}
	err = s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: "namespace", Annotations: annotations}})
	s.Require().NoError(err)

}

func (s *PodServiceAccountEnsurerSuite) TestDoesntCreateWhenNoAnnotation() {
	err := s.ServiceAccountEnsurer.EnsureServiceAccount(context.Background(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "Pod", Namespace: "namespace"}})
	s.Require().NoError(err)
}

func TestPodServiceAccountEnsurerSuite(t *testing.T) {
	suite.Run(t, new(PodServiceAccountEnsurerSuite))
}
