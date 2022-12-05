package otterizecertgen

import (
	"context"
	"github.com/otterize/spire-integration-operator/src/controllers/certificates/jks"
	secretstypes "github.com/otterize/spire-integration-operator/src/controllers/secrets/types"
	"github.com/samber/lo"
)

type KeyPair struct {
	KeyPEM    string `json:"keyPEM"`
	RootCAPEM string `json:"rootCAPEM"`
	CaPEM     string `json:"caPEM"`
	CertPEM   string `json:"certPEM"`
}

type OtterizeCloudClient interface {
	GetTlsKeyPair(ctx context.Context, entryID string) (KeyPair, error)
}

type OtterizeCertificateDataGenerator struct {
	cloudClient OtterizeCloudClient
}

func (m *OtterizeCertificateDataGenerator) GeneratePEM(ctx context.Context, entryID string) (secretstypes.PEMCert, error) {
	keyPair, err := m.cloudClient.GetTlsKeyPair(ctx, entryID)
	if err != nil {
		return secretstypes.PEMCert{}, err
	}
	return secretstypes.PEMCert{Key: []byte(keyPair.KeyPEM), SVID: []byte(keyPair.CertPEM), Bundle: []byte(keyPair.RootCAPEM)}, nil
}

func (m *OtterizeCertificateDataGenerator) GenerateJKS(ctx context.Context, entryID string, password string) (secretstypes.JKSCert, error) {
	keyPair, err := m.cloudClient.GetTlsKeyPair(ctx, entryID)
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

	return secretstypes.JKSCert{KeyStore: keyStoreBytes, TrustStore: trustStoreBytes}, nil

}
