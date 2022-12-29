package otterizeclient

import (
	"context"
	"errors"
	"fmt"
	"github.com/Khan/genqlient/graphql"
	"github.com/amit7itz/goset"
	"github.com/otterize/intents-operator/src/shared/injectablerecorder"
	"github.com/otterize/spire-integration-operator/src/controllers/otterizeclient/otterizegraphql"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type CloudClient struct {
	graphqlClient graphql.Client
	injectablerecorder.InjectableRecorder
	serviceCache map[string]lo.Tuple3[string, string, otterizegraphql.CertificateCustomization]
}

func newGraphqlClient(ctx context.Context) (graphql.Client, error) {
	apiAddress := viper.GetString(OtterizeAPIAddressKey)
	clientID := viper.GetString(ApiClientIdKey)
	secret := viper.GetString(ApiClientSecretKey)

	if clientID == "" {
		return nil, errors.New("missing cloud integration client ID")
	}
	if secret == "" {
		return nil, errors.New("missing cloud integration secret")
	}

	cfg := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		//TokenURL:     "http://app.staging.otterize.com/auth/tokens/token",
		TokenURL:  fmt.Sprintf("%s/auth/tokens/token", apiAddress),
		AuthStyle: oauth2.AuthStyleInParams,
	}

	tokenSrc := cfg.TokenSource(ctx)
	graphqlUrl := fmt.Sprintf("%s/graphql/v1", apiAddress)
	httpClient := oauth2.NewClient(ctx, tokenSrc)

	return graphql.NewClient(graphqlUrl, httpClient), nil
}

func NewCloudClient(ctx context.Context) (*CloudClient, error) {
	gql, err := newGraphqlClient(ctx)
	if err != nil {
		return nil, err
	}
	return &CloudClient{graphqlClient: gql, serviceCache: map[string]lo.Tuple3[string, string, otterizegraphql.CertificateCustomization]{}}, err
}
func (c *CloudClient) GetTLSKeyPair(ctx context.Context, serviceId string) (otterizegraphql.TLSKeyPair, error) {
	tup, ok := c.serviceCache[serviceId]
	if !ok {
		return otterizegraphql.TLSKeyPair{}, fmt.Errorf("service id not registered: %s", serviceId)
	}
	serviceName, namespace, customization := tup.Unpack()
	res, err := otterizegraphql.GetTLSKeyPair(ctx, c.graphqlClient, serviceId, serviceName, namespace, customization)
	if err != nil {
		return otterizegraphql.TLSKeyPair{}, err
	}
	return res.MockService.TlsKeyPair.TLSKeyPair, nil
}

func (c *CloudClient) RegisterK8SPod(ctx context.Context, namespace string, _ string, serviceName string, ttl int32, dnsNames []string) (string, error) {
	res, err := otterizegraphql.ReportKubernetesWorkload(ctx, c.graphqlClient, namespace, serviceName)
	if err != nil {
		return "", err
	}
	certCustomization := otterizegraphql.CertificateCustomization{Ttl: int(ttl), DnsNames: dnsNames}
	c.serviceCache[res.ReportKubernetesWorkload.Id] = lo.Tuple3[string, string, otterizegraphql.CertificateCustomization]{serviceName, namespace, certCustomization}
	return res.ReportKubernetesWorkload.Id, nil
}

func (c *CloudClient) CleanupOrphanK8SPodEntries(_ context.Context, _ string, _ map[string]*goset.Set[string]) error {
	return nil
}
