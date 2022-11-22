package secretstypes

import (
	"context"
	"github.com/samber/lo"
	"strings"
)

type SecretType string
type CertType string

const (
	TlsSecretType = SecretType("TLS")
	JksCertType   = CertType("jks")
	PemCertType   = CertType("pem")
)

func StrToCertType(strCertType string) CertType {
	switch CertType(strings.ToLower(strCertType)) {
	case JksCertType:
		return JksCertType
	case PemCertType:
		return PemCertType
	default:
		return PemCertType
	}
}

type PemConfig struct {
	SvidFileName   string
	BundleFileName string
	KeyFileName    string
}

type CertificateData struct {
	Files     map[string][]byte
	ExpiryStr string
}

func NewPemConfig(svidFileName string, bundleFileName string, keyFileName string) PemConfig {
	newFileNames := PemConfig{}
	newFileNames.SvidFileName, _ = lo.Coalesce(svidFileName, "svid.pem")
	newFileNames.KeyFileName, _ = lo.Coalesce(keyFileName, "key.pem")
	newFileNames.BundleFileName, _ = lo.Coalesce(bundleFileName, "bundle.pem")
	return newFileNames
}

type JksConfig struct {
	KeyStoreFileName   string
	TrustStoreFileName string
	Password           string
}

func NewJksConfig(keystoreFileName string, truststoreFileName string, password string) JksConfig {
	newFileNames := JksConfig{}
	newFileNames.KeyStoreFileName, _ = lo.Coalesce(keystoreFileName, "keystore.jks")
	newFileNames.TrustStoreFileName, _ = lo.Coalesce(truststoreFileName, "truststore.jks")
	newFileNames.Password, _ = lo.Coalesce(password, "password")
	return newFileNames
}

type CertConfig struct {
	CertType  CertType
	JksConfig JksConfig
	PemConfig PemConfig
}

func NewSecretConfig(entryID string, entryHash string, secretName string, namespace string, serviceName string, certConfig CertConfig) SecretConfig {
	return SecretConfig{
		EntryID:     entryID,
		EntryHash:   entryHash,
		SecretName:  secretName,
		Namespace:   namespace,
		ServiceName: serviceName,
		CertConfig:  certConfig,
	}
}

type CertificateDataGenerator interface {
	Generate(ctx context.Context, config SecretConfig) (CertificateData, error)
}

type SecretConfig struct {
	EntryID     string
	EntryHash   string
	SecretName  string
	Namespace   string
	ServiceName string
	CertConfig  CertConfig
}
