package bundles

import (
	"bytes"
	"context"
	"encoding/pem"
	"github.com/otterize/spifferize/src/spireclient"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
)

type Store interface {
	GetTrustBundle(ctx context.Context) (EncodedTrustBundle, error)
}

type store struct {
	bundleClient bundlev1.BundleClient
}

type EncodedTrustBundle struct {
	BundlePEM []byte
}

func NewBundlesStore(spireClient spireclient.ServerClient) Store {
	return &store{bundleClient: spireClient.NewBundleClient()}
}

func (s *store) GetTrustBundle(ctx context.Context) (EncodedTrustBundle, error) {
	bundle, err := s.bundleClient.GetBundle(ctx, &bundlev1.GetBundleRequest{})
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
