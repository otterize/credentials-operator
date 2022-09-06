package entries

import (
	"context"
	"fmt"
	"github.com/otterize/spire-integration-operator/src/spireclient"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc/codes"
	"strings"
)

type Registry interface {
	RegisterK8SPodEntry(ctx context.Context, namespace string, serviceNameLabel string, serviceName string, ttl int32, dnsNames []string) (string, error)
	DeleteK8SPodEntry(ctx context.Context, namespace string, serviceNameLabel string, serviceName string) error
}

type registryImpl struct {
	parentSpiffeID spiffeid.ID
	entryClient    entryv1.EntryClient
}

func NewEntriesRegistry(spireClient spireclient.ServerClient) Registry {
	return &registryImpl{
		parentSpiffeID: spireClient.GetSpiffeID(),
		entryClient:    spireClient.NewEntryClient(),
	}
}

func (r *registryImpl) RegisterK8SPodEntry(ctx context.Context, namespace string, serviceNameLabel string, serviceName string, ttl int32, extraDnsNames []string) (string, error) {
	log := logrus.WithFields(logrus.Fields{"namespace": namespace, "service_name": serviceName})

	trustDomain := r.parentSpiffeID.TrustDomain()
	podSpiffeIDPath := fmt.Sprintf("/otterize/namespace/%s/service/%s", namespace, serviceName)
	parentSpiffeIDPath := r.parentSpiffeID.Path()

	// Spire uses the first DNS name as CN. CN should be a valid dns name.
	commonName := strings.Join([]string{serviceName, namespace}, ".")
	i := slices.Index(extraDnsNames, commonName)
	if i != -1 {
		// Remove common name from extra DNS names to make sure it doesn't appear as duplicate
		extraDnsNames = slices.Delete(extraDnsNames, i, i+1)
	}

	dnsNames := append([]string{commonName}, extraDnsNames...)

	log.Infof("dns_names: %s", dnsNames)

	entry := types.Entry{
		Ttl:      ttl,
		DnsNames: dnsNames,
		SpiffeId: &types.SPIFFEID{
			TrustDomain: trustDomain.String(),
			Path:        podSpiffeIDPath,
		},
		ParentId: &types.SPIFFEID{
			TrustDomain: trustDomain.String(),
			Path:        parentSpiffeIDPath,
		},
		Selectors: []*types.Selector{
			{Type: "k8s", Value: fmt.Sprintf("ns:%s", namespace)},
			{Type: "k8s", Value: fmt.Sprintf("pod-label:%s=%s", serviceNameLabel, serviceName)},
		},
	}

	log.Info("Creating SPIRE server entry")
	batchCreateEntryRequest := entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{&entry}}

	resp, err := r.entryClient.BatchCreateEntry(ctx, &batchCreateEntryRequest)
	if err != nil {
		return "", err
	}

	if len(resp.Results) != 1 {
		return "", fmt.Errorf("unexpected number of results returned from SPIRE server, expected exactly 1 and got %d", len(resp.Results))
	}

	result := resp.Results[0]
	switch result.Status.Code {
	case int32(codes.OK):
		log.WithField("entry_id", result.Entry.Id).Info("SPIRE server entry created")
	case int32(codes.AlreadyExists):
		if shouldUpdateEntry(result.Entry, &entry) {
			entry.Id = result.Entry.Id
			id, err := r.updateSpireEntry(ctx, &entry)
			if err != nil {
				return "", err
			}
			log.WithField("entry_id", id).Info("updated spire entry")
			return id, nil
		} else {
			log.WithField("entry_id", result.Entry.Id).Info("SPIRE server entry already exists")
		}
	default:
		return "", fmt.Errorf("entry failed to create with status %s", result.Status)
	}

	return result.Entry.Id, nil
}

func (r *registryImpl) updateSpireEntry(ctx context.Context, entry *types.Entry) (string, error) {
	batchUpdateEntryRequest := entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{entry}}
	updateResp, err := r.entryClient.BatchUpdateEntry(ctx, &batchUpdateEntryRequest)
	if err != nil {
		return "", fmt.Errorf("entry update failed with error %w", err)
	} else if status := updateResp.Results[0].Status; status.Code != int32(codes.OK) {
		return "", fmt.Errorf("entry update failed with status %s", status)
	}
	return updateResp.Results[0].Entry.Id, nil
}

func (r *registryImpl) paginateDeleteK8SPodEntry(ctx context.Context, namespace string, serviceNameLabel string, serviceName string, pageToken string) (string, error) {
	log := logrus.WithFields(logrus.Fields{"namespace": namespace, "service_name": serviceName})

	trustDomain := r.parentSpiffeID.TrustDomain()
	parentSpiffeIDPath := r.parentSpiffeID.Path()

	listEntriesRequest := entryv1.ListEntriesRequest{
		PageToken: pageToken,
		Filter: &entryv1.ListEntriesRequest_Filter{
			ByParentId: &types.SPIFFEID{
				TrustDomain: trustDomain.String(),
				Path:        parentSpiffeIDPath,
			},
			BySelectors: &types.SelectorMatch{
				Selectors: []*types.Selector{
					{Type: "k8s", Value: fmt.Sprintf("ns:%s", namespace)},
					{Type: "k8s", Value: fmt.Sprintf("pod-label:%s=%s", serviceNameLabel, serviceName)},
				},
				Match: types.SelectorMatch_MATCH_EXACT,
			},
		},
	}

	listResp, err := r.entryClient.ListEntries(ctx, &listEntriesRequest)
	if err != nil {
		return "", fmt.Errorf("list entries failed with error %w", err)
	}

	if len(listResp.Entries) > 0 {
		log.Infof("Deleting %d entries", len(listResp.Entries))
		entryIds := lo.Map(listResp.Entries, func(entry *types.Entry, _ int) string { return entry.Id })
		batchDeleteEntriesRequest := entryv1.BatchDeleteEntryRequest{
			Ids: entryIds,
		}

		deleteResp, err := r.entryClient.BatchDeleteEntry(ctx, &batchDeleteEntriesRequest)
		if err != nil {
			return "", fmt.Errorf("entry delete failed with error %w", err)
		}

		errStatuses := lo.Filter(deleteResp.Results, func(res *entryv1.BatchDeleteEntryResponse_Result, _ int) bool {
			if res.Status == nil {
				return false
			}

			switch res.Status.Code {
			case int32(codes.OK), int32(codes.NotFound):
				return false
			default:
				return true
			}
		})

		if len(errStatuses) != 0 {
			return "", fmt.Errorf("entry delete failed with statuses %v", errStatuses)
		}
	} else {
		log.Info("No entries to delete in this page")
	}

	return listResp.NextPageToken, nil
}

func (r *registryImpl) DeleteK8SPodEntry(ctx context.Context, namespace string, serviceNameLabel string, serviceName string) error {
	log := logrus.WithFields(logrus.Fields{"namespace": namespace, "service_name": serviceName})
	pageToken := ""
	pages := 0
	for pages == 0 || pageToken != "" {
		log.Infof("Iterating over paginated list request, page number %d", pages+1)
		nextPageToken, err := r.paginateDeleteK8SPodEntry(ctx, namespace, serviceNameLabel, serviceName, pageToken)
		if err != nil {
			return err
		}
		pages++
		pageToken = nextPageToken
	}

	return nil
}

func shouldUpdateEntry(createResultEntry *types.Entry, desiredEntry *types.Entry) bool {
	return createResultEntry.Ttl != desiredEntry.Ttl || !slices.Equal(createResultEntry.DnsNames, desiredEntry.DnsNames)
}
