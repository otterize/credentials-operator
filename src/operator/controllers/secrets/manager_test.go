package secrets

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/otterize/spire-integration-operator/src/controllers/metadata"
	"github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
	mock_certificates "github.com/otterize/spire-integration-operator/src/mocks/certificates"
	mock_client "github.com/otterize/spire-integration-operator/src/mocks/controller-runtime/client"
	"github.com/otterize/spire-integration-operator/src/testdata"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
	"time"
)

type ManagerSuite struct {
	suite.Suite
	controller  *gomock.Controller
	client      *mock_client.MockClient
	mockCertGen *mock_certificates.MockCertificateDataGenerator
	manager     *KubernetesSecretsManager
}

func (s *ManagerSuite) SetupTest() {
	s.controller = gomock.NewController(s.T())
	s.client = mock_client.NewMockClient(s.controller)
	s.mockCertGen = mock_certificates.NewMockCertificateDataGenerator(s.controller)
	s.manager = NewSecretManager(s.client, s.mockCertGen)

	s.client.EXPECT().Scheme().AnyTimes()
}

type TLSSecretMatcher struct {
	name      string
	namespace string
	tlsData   *map[string][]byte
}

func (m *TLSSecretMatcher) Matches(x interface{}) bool {
	secret, ok := x.(*corev1.Secret)
	if !ok {
		return false
	}

	if secret.Name != m.name || secret.Namespace != m.namespace {
		return false
	}

	if secret.Labels == nil || secret.Labels[metadata.SecretTypeLabel] != string(secretstypes.TlsSecretType) {
		return false
	}

	if m.tlsData != nil && !reflect.DeepEqual(secret.Data, *m.tlsData) {
		return false
	}

	return true
}

func (m *TLSSecretMatcher) String() string {
	return fmt.Sprintf("TLSSecretsMatcher(name=%s, namespace=%s)", m.name, m.namespace)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_NoExistingSecret() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(errors.NewNotFound(schema.GroupResource{}, ""))

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)
	entryId := "/test"

	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType("pem"), PemConfig: secretstypes.NewPemConfig("", "", "")}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	certData := secretstypes.CertificateData{Files: map[string][]byte{
		certConfig.PemConfig.BundleFileName: testData.BundlePEM,
		certConfig.PemConfig.KeyFileName:    testData.KeyPEM,
		certConfig.PemConfig.SvidFileName:   testData.SVIDPEM},
	}
	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Create(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData:   &certData.Files,
		},
	).Return(nil)

	err = s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_NeedsRefresh() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")
	entryId := "/test"

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryIDAnnotation:               entryId,
					metadata.CertTypeAnnotation:                       "pem",
				},
			},
		}
	})

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)

	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType("pem"), PemConfig: secretstypes.NewPemConfig("", "", "")}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	certData := secretstypes.CertificateData{Files: map[string][]byte{
		certConfig.PemConfig.BundleFileName: testData.BundlePEM,
		certConfig.PemConfig.KeyFileName:    testData.KeyPEM,
		certConfig.PemConfig.SvidFileName:   testData.SVIDPEM},
	}

	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData:   &certData.Files,
		},
	).Return(nil)

	err = s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_NoRefreshNeeded() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")
	entryId := "/test"

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels: map[string]string{
					metadata.SecretTypeLabel: string(secretstypes.TlsSecretType),
				},
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryIDAnnotation:               entryId,
					metadata.CertTypeAnnotation:                       "pem",
				},
			},
		}
	})

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
		},
	).Return(nil)

	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType("pem"), PemConfig: secretstypes.NewPemConfig("", "", "")}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	err := s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_UpdateNeeded_NewSecrets() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryHashAnnotation:             "",
					metadata.CertTypeAnnotation:                       "pem",
				},
			},
		}
	})

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)

	entryId := "/test"

	newSecrets := secretstypes.NewPemConfig("different", "names", "this-time")

	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType("pem"), PemConfig: newSecrets}

	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData: &map[string][]byte{
				newSecrets.BundleFileName: testData.BundlePEM,
				newSecrets.KeyFileName:    testData.KeyPEM,
				newSecrets.SvidFileName:   testData.SVIDPEM,
			},
		},
	).Return(nil)

	err = s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_UpdateNeeded_EntryHashChanged() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryHashAnnotation:             "",
					metadata.CertTypeAnnotation:                       "pem",
				},
			},
		}
	})

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)

	entryId := "/test"

	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType("pem"), PemConfig: secretFileNames}

	newEntryHash := "New-Hash"
	secretConf := secretstypes.NewSecretConfig(entryId, newEntryHash, secretName, namespace, serviceName, certConfig)

	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData: &map[string][]byte{
				secretFileNames.BundleFileName: testData.BundlePEM,
				secretFileNames.KeyFileName:    testData.KeyPEM,
				secretFileNames.SvidFileName:   testData.SVIDPEM,
			},
		},
	).Return(nil)

	err = s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_UpdateNeeded_CertTypeChanged_jksToPem() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryHashAnnotation:             "",
					metadata.CertTypeAnnotation:                       "jks",
				},
			},
		}
	})

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)

	entryId := "/test"

	newCertType := "pem"
	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType(newCertType), PemConfig: secretstypes.NewPemConfig("", "", "")}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	certData := secretstypes.CertificateData{Files: map[string][]byte{
		certConfig.PemConfig.BundleFileName: testData.BundlePEM,
		certConfig.PemConfig.KeyFileName:    testData.KeyPEM,
		certConfig.PemConfig.SvidFileName:   testData.SVIDPEM},
	}
	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData:   &certData.Files,
		},
	).Return(nil)

	err = s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_EnsureTLSSecret_ExistingSecretFound_UpdateNeeded_CertTypeChanged_PemToJks() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	secretFileNames := secretstypes.NewPemConfig("", "", "")

	s.client.EXPECT().Get(
		gomock.Any(),
		types.NamespacedName{Name: secretName, Namespace: namespace},
		gomock.Any(),
	).Return(nil).Do(func(ctx context.Context, key client.ObjectKey, found *corev1.Secret) {
		*found = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Annotations: map[string]string{
					metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
					metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
					metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
					metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
					metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
					metadata.TLSSecretEntryHashAnnotation:             "",
					metadata.CertTypeAnnotation:                       "pem",
				},
			},
		}
	})

	entryId := "/test"

	newCertType := "jks"
	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType(newCertType), JksConfig: secretstypes.NewJksConfig("", "", "")}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	jks := secretstypes.JKSCert{KeyStore: []byte("test1234"), TrustStore: []byte("testy-test")}
	certData := secretstypes.CertificateData{Files: map[string][]byte{
		certConfig.JksConfig.KeyStoreFileName:   jks.KeyStore,
		certConfig.JksConfig.TrustStoreFileName: jks.TrustStore},
	}
	s.mockCertGen.EXPECT().GenerateJKS(gomock.Any(), secretConf.EntryID, "password").Return(jks, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData:   &certData.Files,
		},
	).Return(nil)

	err := s.manager.EnsureTLSSecret(context.Background(), secretConf, nil)
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_RefreshTLSSecrets_RefreshNeeded() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	entryId := "/test"
	secretFileNames := secretstypes.NewPemConfig("", "", "")
	certType := "pem"

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Annotations: map[string]string{
				metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Format(time.RFC3339),
				metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
				metadata.TLSSecretEntryIDAnnotation:               entryId,
				metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
				metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
				metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
				metadata.CertTypeAnnotation:                       certType,
			},
		},
	}
	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.SecretList{}),
		gomock.AssignableToTypeOf(&client.MatchingLabels{}),
	).Do(func(ctx context.Context, list *corev1.SecretList, opts ...client.ListOption) {
		*list = corev1.SecretList{
			Items: []corev1.Secret{secret},
		}
	})

	testData, err := testdata.LoadTestData()
	s.Require().NoError(err)
	certConfig := secretstypes.CertConfig{CertType: secretstypes.StrToCertType(certType), PemConfig: secretFileNames}
	secretConf := secretstypes.NewSecretConfig(entryId, "", secretName, namespace, serviceName, certConfig)

	pem := secretstypes.PemCert{Key: testData.KeyPEM, Bundle: testData.BundlePEM, Svid: testData.SVIDPEM}
	s.mockCertGen.EXPECT().GeneratePem(gomock.Any(), secretConf.EntryID).Return(pem, nil)

	s.client.EXPECT().Update(
		gomock.Any(),
		&TLSSecretMatcher{
			namespace: namespace,
			name:      secretName,
			tlsData: &map[string][]byte{
				secretFileNames.BundleFileName: testData.BundlePEM,
				secretFileNames.KeyFileName:    testData.KeyPEM,
				secretFileNames.SvidFileName:   testData.SVIDPEM,
			},
		},
	).Return(nil)

	err = s.manager.RefreshTLSSecrets(context.Background())
	s.Require().NoError(err)
}

func (s *ManagerSuite) TestManager_RefreshTLSSecrets_NoRefreshNeeded() {
	namespace := "test_namespace"
	secretName := "test_secretname"
	serviceName := "test_servicename"
	entryId := "/test"
	secretFileNames := secretstypes.NewPemConfig("", "", "")

	s.client.EXPECT().List(
		gomock.Any(),
		gomock.AssignableToTypeOf(&corev1.SecretList{}),
		gomock.AssignableToTypeOf(&client.MatchingLabels{}),
	).Do(func(ctx context.Context, list *corev1.SecretList, opts ...client.ListOption) {
		*list = corev1.SecretList{
			Items: []corev1.Secret{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: namespace,
						Annotations: map[string]string{
							metadata.TLSSecretSVIDExpiryAnnotation:            time.Now().Add(2 * secretExpiryDelta).Format(time.RFC3339),
							metadata.TLSSecretRegisteredServiceNameAnnotation: serviceName,
							metadata.TLSSecretEntryIDAnnotation:               entryId,
							metadata.SVIDFileNameAnnotation:                   secretFileNames.SvidFileName,
							metadata.BundleFileNameAnnotation:                 secretFileNames.BundleFileName,
							metadata.KeyFileNameAnnotation:                    secretFileNames.KeyFileName,
							metadata.CertTypeAnnotation:                       "pem",
						},
					},
				},
			},
		}
	})

	err := s.manager.RefreshTLSSecrets(context.Background())
	s.Require().NoError(err)
}

func TestRunManagerSuite(t *testing.T) {
	suite.Run(t, new(ManagerSuite))
}
