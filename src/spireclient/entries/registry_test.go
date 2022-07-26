package entries

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	mock_entryv1 "github.com/otterize/spifferize/src/mocks/entryv1"
	mock_spireclient "github.com/otterize/spifferize/src/mocks/spireclient"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"testing"
)

var (
	trustDomain = spiffeid.RequireTrustDomainFromString("example.org")
)

type RegistrySuite struct {
	suite.Suite
	controller  *gomock.Controller
	spireClient *mock_spireclient.MockServerClient
	entryClient *mock_entryv1.MockEntryClient
	registry    Registry
}

func (s *RegistrySuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.spireClient = mock_spireclient.NewMockServerClient(s.controller)
	s.entryClient = mock_entryv1.NewMockEntryClient(s.controller)
	clientSpiffeID, err := spiffeid.FromPath(trustDomain, "/client")
	s.Require().NoError(err)
	s.spireClient.EXPECT().GetSpiffeID().Return(clientSpiffeID)
	s.spireClient.EXPECT().NewEntryClient().Return(s.entryClient)
	s.registry = NewEntriesRegistry(s.spireClient)
}

func (s *RegistrySuite) TearDownTest() {
	s.spireClient.EXPECT().Close()
	s.spireClient.Close()
}

func (s *RegistrySuite) TestRegistry_RegisterK8SPodEntry() {
	for _, statusCode := range []codes.Code{codes.OK, codes.AlreadyExists} {
		s.Run(fmt.Sprintf("status_code=%d", statusCode), func() {
			namespace := "test-namespace"
			serviceNameLabel := "test/service-name"
			serviceName := "test-service-name"
			spiffeID, err := spiffeid.FromPath(trustDomain, "/otterize/namespace/test-namespace/service/test-service-name")
			s.Require().NoError(err)

			response := entryv1.BatchCreateEntryResponse{
				Results: []*entryv1.BatchCreateEntryResponse_Result{
					{
						Status: &types.Status{Code: int32(statusCode)},
						Entry: &types.Entry{
							Id: "test",
							SpiffeId: &types.SPIFFEID{
								TrustDomain: spiffeID.TrustDomain().String(),
								Path:        spiffeID.Path(),
							},
						},
					},
				},
			}

			s.entryClient.EXPECT().BatchCreateEntry(gomock.Any(), gomock.Any()).Return(&response, nil)

			if statusCode == codes.AlreadyExists {
				updateResponse := entryv1.BatchUpdateEntryResponse{
					Results: []*entryv1.BatchUpdateEntryResponse_Result{
						{
							Status: &types.Status{Code: int32(codes.OK)},
							Entry: &types.Entry{Id: "test",
								SpiffeId: &types.SPIFFEID{TrustDomain: spiffeID.TrustDomain().String(),
									Path: spiffeID.Path(),
								},
							},
						},
					},
				}

				s.entryClient.EXPECT().BatchUpdateEntry(gomock.Any(), gomock.Any()).Return(&updateResponse, nil)
			}

			entryId, err := s.registry.RegisterK8SPodEntry(context.Background(),
				namespace,
				serviceNameLabel,
				serviceName,
				0,
				[]string{})

			s.Require().NoError(err)
			s.Require().Equal(entryId, response.Results[0].Entry.Id)
		})
	}

}

func (s *RegistrySuite) TestShouldUpdateEntry() {
	spiffeID, _ := spiffeid.FromPath(trustDomain, "/otterize/namespace/test-namespace/service/test-service-name")
	entry1 := &types.Entry{
		Id:       "test",
		Ttl:      555,
		DnsNames: []string{"hi.com"},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().String(),
			Path:        spiffeID.Path(),
		},
	}
	entry2 := &types.Entry{
		Id:       "test",
		Ttl:      555,
		DnsNames: []string{"hi1.com"},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().String(),
			Path:        spiffeID.Path(),
		},
	}
	entry3 := &types.Entry{
		Id:       "test",
		Ttl:      666,
		DnsNames: []string{"hi.com"},
		SpiffeId: &types.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().String(),
			Path:        spiffeID.Path(),
		},
	}
	s.Require().True(shouldUpdateEntry(entry1, entry2))
	s.Require().True(shouldUpdateEntry(entry1, entry3))
	s.Require().True(shouldUpdateEntry(entry2, entry3))
}

func TestRunRegistrySuite(t *testing.T) {
	suite.Run(t, new(RegistrySuite))
}
