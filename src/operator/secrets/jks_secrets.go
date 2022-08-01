package secrets

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/otterize/spire-integration-operator/src/spireclient/bundles"
	"github.com/otterize/spire-integration-operator/src/spireclient/svids"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"time"
)

func svidToKeyStore(svid svids.EncodedX509SVID) ([]byte, error) {
	var certChain []keystore.Certificate
	for _, certPEM := range bytes.SplitAfter(svid.SVIDPEM, []byte("-----END CERTIFICATE-----\n")) {
		if len(certPEM) != 0 {
			cert := keystore.Certificate{
				Type:    "X509",
				Content: certPEM,
			}
			certChain = append(certChain, cert)
		}
	}
	keyStore := keystore.New()
	block, _ := pem.Decode(svid.KeyPEM)
	if block == nil {
		return nil, errors.New("error decoding private key PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	pk := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       keyDER,
		CertificateChain: certChain,
	}
	err = keyStore.SetPrivateKeyEntry("pkey", pk, []byte("password"))
	if err != nil {
		return nil, err
	}
	keyStoreBytesBuffer := new(bytes.Buffer)
	err = keyStore.Store(keyStoreBytesBuffer, []byte("password"))
	if err != nil {
		return nil, err
	}
	return keyStoreBytesBuffer.Bytes(), nil
}

func trustBundleToTrustStore(trustBundle bundles.EncodedTrustBundle) ([]byte, error) {
	trustStore := keystore.New()
	for i, caPEM := range bytes.SplitAfter(trustBundle.BundlePEM, []byte("-----END CERTIFICATE-----\n")) {
		if len(caPEM) != 0 {
			ca := keystore.TrustedCertificateEntry{
				CreationTime: time.Now(),
				Certificate: keystore.Certificate{
					Type:    "X509",
					Content: caPEM,
				},
			}
			err := trustStore.SetTrustedCertificateEntry(fmt.Sprintf("ca-%d", i), ca)
			if err != nil {
				return nil, err
			}
		}
	}
	trustStoreBytesBuffer := new(bytes.Buffer)
	err := trustStore.Store(trustStoreBytesBuffer, []byte("password"))
	if err != nil {
		return nil, err
	}
	return trustStoreBytesBuffer.Bytes(), nil
}
