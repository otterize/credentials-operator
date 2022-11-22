package spirecertgen

import (
	"context"
	"fmt"
	"github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/bundles"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/svids"
	"time"
)

type SpireCertificateDataGenerator struct {
	bundlesStore bundles.Store
	svidsStore   svids.Store
}

func NewSpireCertificateDataGenerator(bundlesStore bundles.Store, svidsStore svids.Store) *SpireCertificateDataGenerator {
	return &SpireCertificateDataGenerator{bundlesStore: bundlesStore, svidsStore: svidsStore}
}

func (m *SpireCertificateDataGenerator) Generate(ctx context.Context, config secretstypes.SecretConfig) (secretstypes.CertificateData, error) {
	trustBundle, err := m.bundlesStore.GetTrustBundle(ctx)
	if err != nil {
		return secretstypes.CertificateData{}, err
	}

	privateKey, err := m.svidsStore.GeneratePrivateKey()

	if err != nil {
		return secretstypes.CertificateData{}, err
	}

	svid, err := m.svidsStore.GetX509SVID(ctx, config.EntryID, privateKey)
	if err != nil {
		return secretstypes.CertificateData{}, err
	}

	expiry := time.Unix(svid.ExpiresAt, 0)
	expiryStr := expiry.Format(time.RFC3339)

	secretData, err := m.generateSecretData(trustBundle, svid, config.CertConfig)
	if err != nil {
		return secretstypes.CertificateData{}, nil
	}
	return secretstypes.CertificateData{Files: secretData, ExpiryStr: expiryStr}, nil
}

func (m *SpireCertificateDataGenerator) generateSecretData(trustBundle bundles.EncodedTrustBundle, svid svids.EncodedX509SVID, certConfig secretstypes.CertConfig) (map[string][]byte, error) {
	switch certConfig.CertType {
	case secretstypes.JksCertType:
		trustStoreBytes, err := trustBundleToTrustStore(trustBundle, certConfig.JksConfig.Password)
		if err != nil {
			return nil, err
		}

		keyStoreBytes, err := svidToKeyStore(svid, certConfig.JksConfig.Password)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{
			certConfig.JksConfig.TrustStoreFileName: trustStoreBytes,
			certConfig.JksConfig.KeyStoreFileName:   keyStoreBytes,
		}, nil
	case secretstypes.PemCertType:
		return map[string][]byte{
			certConfig.PemConfig.BundleFileName: trustBundle.BundlePEM,
			certConfig.PemConfig.KeyFileName:    svid.KeyPEM,
			certConfig.PemConfig.SvidFileName:   svid.SVIDPEM,
		}, nil
	default:
		return nil, fmt.Errorf("failed generating secret data. unsupported cert type %s", certConfig.CertType)
	}
}
