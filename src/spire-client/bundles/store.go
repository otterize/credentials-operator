package bundles

import (
	"bytes"
	"context"
	"encoding/pem"
	spire_client "github.com/otterize/spifferize/src/spire-client"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
)

type Store struct {
	SpireClient spire_client.ServerClient
}

type EncodedTrustBundle struct {
	BundlePEM []byte
}

func NewBundlesStore(spireClient spire_client.ServerClient) *Store {
	return &Store{SpireClient: spireClient}
}

func (s *Store) GetTrustBundle(ctx context.Context) (EncodedTrustBundle, error) {
	bundleClient := s.SpireClient.NewBundleClient()

	bundle, err := bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return EncodedTrustBundle{}, err
	}

	bundlePEM := new(bytes.Buffer)
	for _, rootCA := range bundle.X509Authorities {
		if err := pem.Encode(bundlePEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA.Asn1,
		}); err != nil {
			return EncodedTrustBundle{}, err
		}
	}

	return EncodedTrustBundle{BundlePEM: bundlePEM.Bytes()}, nil
}
