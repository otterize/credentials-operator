package gcpcredentialsagent

import (
	"context"
	"github.com/otterize/credentials-operator/src/shared/apiutils"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/otterize/intents-operator/src/shared/gcpagent"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	// GCPAgentFinalizer indicates that cleanup on GCP service account is needed upon termination.
	GCPAgentFinalizer = "credentials-operator.otterize.com/gcp-service-account"

	// GCPOtterizeServiceAccountLabel is used to label service accounts generated by the credentials-operator
	GCPOtterizeServiceAccountLabel = "credentials-operator.otterize.com/gco-service-account-managed"

	// GCPWorkloadIdentityAnnotation is used by GCP workload identity to link between service accounts
	GCPWorkloadIdentityAnnotation = "iam.gke.io/gcp-service-account"
	GCPWorkloadIdentityNotSet     = "false"
)

type Agent struct {
	*gcpagent.Agent
}

func NewGCPCredentialsAgent(gcpAgent *gcpagent.Agent) *Agent {
	return &Agent{gcpAgent}
}

func (a *Agent) FinalizerName() string {
	return GCPAgentFinalizer
}

func (a *Agent) ServiceAccountLabel() string {
	return GCPOtterizeServiceAccountLabel
}

func (a *Agent) OnPodAdmission(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount, dryRun bool) error {
	// The GCP agent does not need to do anything on pod admission
	return nil
}

func (a *Agent) OnPodUpdate(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error) {
	apiutils.AddAnnotation(serviceAccount, GCPWorkloadIdentityAnnotation, GCPWorkloadIdentityNotSet)
	return true, false, nil
}

func (a *Agent) OnServiceAccountUpdate(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	// Check if we should update the service account - if the annotation is not set
	if value, ok := serviceAccount.Annotations[GCPWorkloadIdentityAnnotation]; !ok || value != GCPWorkloadIdentityNotSet {
		logger.Debug("ServiceAccount GCP workload identity annotation is already set, skipping")
		return false, false, nil
	}

	// Annotate the namespace to connect workload identity
	requeue, err = a.AnnotateGKENamespace(ctx, serviceAccount.Namespace)
	if err != nil {
		return false, false, errors.Errorf("failed to annotate namespace: %w", err)
	}
	if requeue {
		// TODO: maybe do apierrors.IsConflict(err) check instead?
		return false, true, nil
	}

	// Create IAMServiceAccount (Creates a GCP service account)
	err = a.CreateAndConnectGSA(ctx, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, false, errors.Errorf("failed to create and connect GSA: %w", err)
	}

	// Annotate the service account with the GCP IAM role
	gsaFullName := a.GetGSAFullName(serviceAccount.Namespace, serviceAccount.Name)
	apiutils.AddAnnotation(serviceAccount, GCPWorkloadIdentityAnnotation, gsaFullName)
	return true, false, nil
}

func (a *Agent) OnServiceAccountTermination(ctx context.Context, serviceAccount *corev1.ServiceAccount) error {
	return a.DeleteGSA(ctx, serviceAccount.Namespace, serviceAccount.Name)
}
