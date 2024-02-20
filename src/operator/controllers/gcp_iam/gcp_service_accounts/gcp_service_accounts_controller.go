package gcp_service_accounts

import (
	"context"
	"github.com/GoogleCloudPlatform/k8s-config-connector/operator/pkg/k8s"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type GCPRolePolicyManager interface {
	GetGSAFullName(namespace string, name string) string
	DeleteGSA(ctx context.Context, namespace string, name string) error
	CreateAndConnectGSA(ctx context.Context, client client.Client, namespaceName, accountName string) error
	AnnotateEKSNamespace(ctx context.Context, client client.Client, namespaceName string) (requeue bool, err error)
}

type Reconciler struct {
	client   client.Client
	gcpAgent GCPRolePolicyManager
}

func NewReconciler(client client.Client, gcpAgent GCPRolePolicyManager) *Reconciler {
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
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": req.Name, "namespace": req.Namespace})

	serviceAccount := corev1.ServiceAccount{}

	err := r.client.Get(ctx, req.NamespacedName, &serviceAccount)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	// Handle service account cleanup
	isReferencedByPods, exists := getServiceAccountTagging(&serviceAccount)
	if !exists {
		logger.Debugf("serviceAccount not labeled with %s, skipping", metadata.OtterizeServiceAccountLabel)
		return ctrl.Result{}, nil
	}

	isNoLongerReferencedByPodsOrIsBeingDeleted := serviceAccount.DeletionTimestamp != nil || !isReferencedByPods

	if isNoLongerReferencedByPodsOrIsBeingDeleted {
		err = r.gcpAgent.DeleteGSA(ctx, req.Namespace, req.Name)
		if err != nil {
			return ctrl.Result{}, errors.Errorf("failed to remove service account: %w", err)
		}

		if serviceAccount.DeletionTimestamp != nil {
			updatedServiceAccount := serviceAccount.DeepCopy()
			// TODO: check finalizer logic
			if controllerutil.RemoveFinalizer(updatedServiceAccount, metadata.GCPSAFinalizer) {
				err := r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
				if err != nil {
					if apierrors.IsConflict(err) {
						return ctrl.Result{Requeue: true}, nil
					}
					return ctrl.Result{}, errors.Wrap(err)
				}
			}
		}
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
	requeue, err := r.gcpAgent.AnnotateEKSNamespace(ctx, r.client, req.Namespace)
	if err != nil {
		return ctrl.Result{}, errors.Errorf("failed to remove service account: %w", err)
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

func getServiceAccountTagging(serviceAccount *corev1.ServiceAccount) (hasPods bool, exists bool) {
	// TODO: rethink logic
	if serviceAccount.Labels == nil {
		return false, false
	}

	labelValue, hasLabel := serviceAccount.Labels[metadata.OtterizeServiceAccountLabel]
	annotationValue, hasAnnotation := serviceAccount.Annotations[k8s.WorkloadIdentityAnnotation]
	shouldUpdate := annotationValue == metadata.GCPWorkloadIdentityNotSet
	return labelValue == metadata.OtterizeServiceAccountHasPodsValue, hasLabel && hasAnnotation && shouldUpdate
}
