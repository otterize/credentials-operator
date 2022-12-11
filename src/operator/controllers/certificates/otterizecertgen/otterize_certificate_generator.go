package otterizecertgen

import (
	"context"
	"github.com/otterize/spire-integration-operator/src/controllers/certificates/jks"
	"github.com/otterize/spire-integration-operator/src/controllers/otterizeclient/otterizegraphql"
	secretstypes "github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
	"github.com/samber/lo"
	"time"
)

type OtterizeCloudClient interface {
	GetTLSKeyPair(ctx context.Context, serviceId string, certificateCustomization otterizegraphql.CertificateCustomization) (otterizegraphql.TLSKeyPair, error)
}

type OtterizeCertificateDataGenerator struct {
	cloudClient OtterizeCloudClient
}

func keyPairToExpiryStr(keyPair otterizegraphql.TLSKeyPair) string {
	expiry := time.Unix(int64(keyPair.ExpiresAt), 0)
	expiryStr := expiry.Format(time.RFC3339)
	return expiryStr
}

func (m *OtterizeCertificateDataGenerator) GeneratePEM(ctx context.Context, serviceId string) (secretstypes.PEMCert, error) {
	keyPair, err := m.cloudClient.GetTLSKeyPair(ctx, serviceId, otterizegraphql.CertificateCustomization{})
	if err != nil {
		return secretstypes.PEMCert{}, err
	}
	expiryStr := keyPairToExpiryStr(keyPair)
	return secretstypes.PEMCert{Key: []byte(keyPair.KeyPEM), SVID: []byte(keyPair.CertPEM), Bundle: []byte(keyPair.RootCAPEM), Expiry: expiryStr}, nil
}

func (m *OtterizeCertificateDataGenerator) GenerateJKS(ctx context.Context, serviceId string, password string) (secretstypes.JKSCert, error) {
	keyPair, err := m.cloudClient.GetTLSKeyPair(ctx, serviceId, otterizegraphql.CertificateCustomization{})
	if err != nil {
		return secretstypes.JKSCert{}, err
	}
	certChain := lo.Map([]string{keyPair.CertPEM, keyPair.CaPEM, keyPair.CaPEM}, func(cert string, _ int) []byte { return []byte(cert) })
	keyStore, err := jks.PemToKeyStore(certChain, []byte(keyPair.KeyPEM), password)
	if err != nil {
		return secretstypes.JKSCert{}, err
	}
	keyStoreBytes, err := jks.ByteDumpKeyStore(keyStore, password)
	if err != nil {
		return secretstypes.JKSCert{}, err
	}

	trustStore, err := jks.CASliceToTrustStore(certChain[1:])
	if err != nil {
		return secretstypes.JKSCert{}, err
	}
	trustStoreBytes, err := jks.ByteDumpKeyStore(trustStore, password)
	if err != nil {
		return secretstypes.JKSCert{}, err
	}

	expiryStr := keyPairToExpiryStr(keyPair)

	return secretstypes.JKSCert{KeyStore: keyStoreBytes, TrustStore: trustStoreBytes, Expiry: expiryStr}, nil

}
