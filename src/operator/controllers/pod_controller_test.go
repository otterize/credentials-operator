package controllers

import (
	"github.com/golang/mock/gomock"
	mock_spireclient "github.com/otterize/spifferize/src/mocks/client"
	mock_client "github.com/otterize/spifferize/src/mocks/controller-runtime/client"
	mock_bundles "github.com/otterize/spifferize/src/mocks/spireclient/bundles"
	mock_svids "github.com/otterize/spifferize/src/mocks/spireclient/svids"
	"github.com/stretchr/testify/suite"
	"testing"
)

type PodControllerSuite struct {
	suite.Suite
	controller   *gomock.Controller
	client       *mock_client.MockClient
	spireClient  *mock_spireclient.MockServerClient
	bundlesStore *mock_bundles.MockStore
	svidsStore   *mock_svids.MockStore
}

func (s *PodControllerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.bundlesStore = mock_bundles.NewMockStore(s.controller)
	s.svidsStore = mock_svids.NewMockStore(s.controller)
	//s.manager = NewSecretsManager(s.client, s.bundlesStore, s.svidsStore)
}

func TestRunPodControllerSuite(t *testing.T) {
	suite.Run(t, new(PodControllerSuite))
}
