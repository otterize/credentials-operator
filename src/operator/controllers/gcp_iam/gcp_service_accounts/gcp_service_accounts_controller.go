package gcp_service_accounts

import (
	"context"
	"github.com/GoogleCloudPlatform/k8s-config-connector/operator/pkg/k8s"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type GCPServiceAccountManager interface {
	GetGSAFullName(namespace string, name string) string
	DeleteGSA(ctx context.Context, c client.Client, namespaceName string, ksaName string) error
	CreateAndConnectGSA(ctx context.Context, c client.Client, namespaceName, ksaName string) error
	AnnotateGKENamespace(ctx context.Context, c client.Client, namespaceName string) (bool, error)
}

type Reconciler struct {
	client   client.Client
	gcpAgent GCPServiceAccountManager
}

func NewReconciler(client client.Client, gcpAgent GCPServiceAccountManager) *Reconciler {
	return &Reconciler{
		client:   client,
		gcpAgent: gcpAgent,
	}
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&corev1.ServiceAccount{}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	serviceAccount := corev1.ServiceAccount{}
	err := r.client.Get(ctx, req.NamespacedName, &serviceAccount)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	isReferencedByPods, hasLabel := r.serviceHasGCPLabels(serviceAccount)
	if !hasLabel {
		return ctrl.Result{}, nil
	}

	// Perform cleanup if the service account is being deleted or no longer referenced by pods
	if serviceAccount.DeletionTimestamp != nil || !isReferencedByPods {
		return r.HandleServiceCleanup(ctx, req, serviceAccount)
	}

	return r.HandleServiceUpdate(ctx, req, serviceAccount)
}

func (r *Reconciler) HandleServiceCleanup(ctx context.Context, req ctrl.Request, serviceAccount corev1.ServiceAccount) (ctrl.Result, error) {
	err := r.gcpAgent.DeleteGSA(ctx, r.client, req.Namespace, req.Name)
	if err != nil {
		return ctrl.Result{}, errors.Errorf("failed to remove service account: %w", err)
	}

	// Remove the finalizer even if the service account is not deleted since it already got cleaned up
	updatedServiceAccount := serviceAccount.DeepCopy()
	if controllerutil.RemoveFinalizer(updatedServiceAccount, metadata.GCPSAFinalizer) {
		// Remove the service account label and annotation
		delete(updatedServiceAccount.Labels, metadata.OtterizeGCPServiceAccountLabel)
		delete(updatedServiceAccount.Annotations, k8s.WorkloadIdentityAnnotation)

		err = r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
		if err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) HandleServiceUpdate(ctx context.Context, req ctrl.Request, serviceAccount corev1.ServiceAccount) (ctrl.Result, error) {
	// Check if we should update the service account - if the annotation is not set
	annotationValue, hasAnnotation := serviceAccount.Annotations[k8s.WorkloadIdentityAnnotation]
	shouldUpdate := annotationValue == metadata.GCPWorkloadIdentityNotSet
	if !hasAnnotation || !shouldUpdate {
		return ctrl.Result{}, nil
	}

	// Add a finalizer label to the service account to block deletion until cleanup is complete
	updatedServiceAccount := serviceAccount.DeepCopy()
	if controllerutil.AddFinalizer(updatedServiceAccount, metadata.GCPSAFinalizer) {
		err := r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
		if err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
	}

	// Annotate the namespace to connect workload identity
	requeue, err := r.gcpAgent.AnnotateGKENamespace(ctx, r.client, req.Namespace)
	if err != nil {
		return ctrl.Result{}, errors.Errorf("failed to annotate namespace: %w", err)
	}
	if requeue {
		// TODO: maybe do apierrors.IsConflict(err) check instead?
		return ctrl.Result{Requeue: true}, nil
	}

	// Create IAMServiceAccount (Creates a GCP service account)
	err = r.gcpAgent.CreateAndConnectGSA(ctx, r.client, req.Namespace, req.Name)
	if err != nil {
		return ctrl.Result{}, errors.Errorf("failed to create and connect GSA: %w", err)
	}

	// Annotate the service account with the GCP IAM role
	// TODO: is it ok to re-use the same updatedServiceAccount?
	gsaFullName := r.gcpAgent.GetGSAFullName(req.Namespace, req.Name)
	updatedServiceAccount.Annotations[k8s.WorkloadIdentityAnnotation] = gsaFullName
	err = r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
	if err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) serviceHasGCPLabels(serviceAccount corev1.ServiceAccount) (bool, bool) {
	if serviceAccount.Labels == nil {
		return false, false
	}
	labelValue, hasLabel := serviceAccount.Labels[metadata.OtterizeGCPServiceAccountLabel]
	return labelValue == metadata.OtterizeServiceAccountHasPodsValue, hasLabel
}
