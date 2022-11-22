package spirecertgen

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/bundles"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/svids"
	mock_bundles "github.com/otterize/spire-integration-operator/src/mocks/spireclient/bundles"
	mock_svids "github.com/otterize/spire-integration-operator/src/mocks/spireclient/svids"
	"github.com/otterize/spire-integration-operator/src/testdata"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

const ExpiryTimeTestStr = "06/24/94"
const ExpiryTimeTestLayout = "01/02/06"

type ManagerSuite struct {
	suite.Suite
	controller    *gomock.Controller
	bundlesStore  *mock_bundles.MockStore
	svidsStore    *mock_svids.MockStore
	certGenerator *SpireCertificateDataGenerator
}

func (s *ManagerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.bundlesStore = mock_bundles.NewMockStore(s.controller)
	s.svidsStore = mock_svids.NewMockStore(s.controller)
	s.certGenerator = NewSpireCertificateDataGenerator(s.bundlesStore, s.svidsStore)

}

func (s *ManagerSuite) mockTLSStores(entryId string, testData testdata.TestData) {
	encodedBundle := bundles.EncodedTrustBundle{BundlePEM: testData.BundlePEM}
	s.bundlesStore.EXPECT().GetTrustBundle(gomock.Any()).Return(encodedBundle, nil)

	privateKey, err := pemutil.ParseECPrivateKey(testData.KeyPEM)
	s.Require().NoError(err)
	s.svidsStore.EXPECT().GeneratePrivateKey().Return(privateKey, nil)

	expiry, err := time.Parse(ExpiryTimeTestLayout, ExpiryTimeTestStr)
	s.Require().NoError(err)

	encodedX509SVID := svids.EncodedX509SVID{
		SVIDPEM:   testData.SVIDPEM,
		KeyPEM:    testData.KeyPEM,
		ExpiresAt: expiry.Unix(),
	}
	s.svidsStore.EXPECT().GetX509SVID(
		gomock.Any(), entryId, privateKey,
	).Return(encodedX509SVID, nil)
}

func (s *ManagerSuite) TestCertGenerator_Generate() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)
	entryId := "/test"

	s.mockTLSStores(entryId, testData)

	certConfig := secretstypes.CertConfig{
		CertType:  secretstypes.StrToCertType("pem"),
		PemConfig: secretstypes.NewPemConfig("", "", ""),
	}

	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	certData, err := s.certGenerator.Generate(context.Background(), secretConf)
	s.Require().NoError(err)
	expiry, err := time.Parse(ExpiryTimeTestLayout, ExpiryTimeTestStr)
	s.Require().NoError(err)
	expiryUnix := time.Unix(expiry.Unix(), 0)
	expectedCertData := secretstypes.CertificateData{
		Files: map[string][]byte{
			certConfig.PemConfig.BundleFileName: testData.BundlePEM,
			certConfig.PemConfig.KeyFileName:    testData.KeyPEM,
			certConfig.PemConfig.SvidFileName:   testData.SVIDPEM,
		},
		ExpiryStr: expiryUnix.Format(time.RFC3339),
	}
	s.Equal(expectedCertData, certData)
}

func (s *ManagerSuite) TestJksTrustStoreCreate() {
	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)
	bundle := bundles.EncodedTrustBundle{BundlePEM: testData.BundlePEM}
	trustBundle, err := trustBundleToTrustStore(bundle, "password")
	s.Require().NoError(err)
	s.Require().NotNil(trustBundle)
}

func (s *ManagerSuite) TestJksKeyStoreCreate() {
	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)
	svid := svids.EncodedX509SVID{SVIDPEM: testData.SVIDPEM, KeyPEM: testData.KeyPEM}
	trustBundle, err := svidToKeyStore(svid, "password")
	s.Require().NoError(err)
	s.Require().NotNil(trustBundle)
}

func TestRunManagerSuite(t *testing.T) {
	suite.Run(t, new(ManagerSuite))
}
