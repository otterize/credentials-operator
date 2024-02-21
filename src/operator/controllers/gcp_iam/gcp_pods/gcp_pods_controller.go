package gcp_pods

import (
	"context"
	"github.com/GoogleCloudPlatform/k8s-config-connector/operator/pkg/k8s"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/otterize/credentials-operator/src/shared/apiutils"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type GCPServiceAccountManager interface {
	GetGSAFullName(namespace string, name string) string
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
	err := apiutils.InitPodServiceAccountIndexField(mgr)
	if err != nil {
		return errors.Wrap(err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&corev1.Pod{}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := corev1.Pod{}
	err := r.client.Get(ctx, req.NamespacedName, &pod)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	if pod.DeletionTimestamp != nil {
		return r.HandlePodDeletion(ctx, pod)
	}
	return r.HandlePodUpdate(ctx, pod)
}

func (r *Reconciler) HandlePodDeletion(ctx context.Context, pod corev1.Pod) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(&pod, metadata.GCPSAFinalizer) {
		return ctrl.Result{}, nil
	}

	// Find all pods that have the same service account
	saConsumers, err := apiutils.GetPodServiceAccountConsumers(ctx, r.client, pod)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err)
	}

	// Get only the pods that are GCP consumers - also handles case where label was removed from the pod.
	gcpSAConsumers := lo.Filter(saConsumers, func(filteredPod corev1.Pod, _ int) bool {
		return controllerutil.ContainsFinalizer(&pod, metadata.GCPSAFinalizer) || pod.UID == filteredPod.UID
	})

	// Check if this is the last pod linked to this SA.
	if len(gcpSAConsumers) == 1 && gcpSAConsumers[0].UID == pod.UID {
		var serviceAccount corev1.ServiceAccount
		err := r.client.Get(ctx, types.NamespacedName{Name: pod.Spec.ServiceAccountName, Namespace: pod.Namespace}, &serviceAccount)
		if err != nil {
			// service account can be deleted before the pods go down, in which case cleanup has already occurred, so just let the pod terminate.
			if apierrors.IsNotFound(err) {
				return apiutils.RemoveFinalizerFromPod(ctx, r.client, pod, metadata.GCPSAFinalizer)
			}
			return ctrl.Result{}, errors.Wrap(err)
		}

		updatedServiceAccount := serviceAccount.DeepCopy()
		if updatedServiceAccount.Labels == nil {
			updatedServiceAccount.Labels = make(map[string]string)
		}

		// Normally we would call the other reconciler, but because this is blocking the removal of a pod finalizer,
		// we instead update the ServiceAccount and let it do the hard work, so we can remove the pod finalizer ASAP.
		updatedServiceAccount.Labels[metadata.OtterizeGCPServiceAccountLabel] = metadata.OtterizeServiceAccountHasNoPodsValue
		err = r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
		if err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			// service account can be deleted before the pods go down, in which case cleanup has already occurred, so just let the pod terminate.
			if apierrors.IsNotFound(err) {
				return apiutils.RemoveFinalizerFromPod(ctx, r.client, pod, metadata.GCPSAFinalizer)
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
	}

	// In case there's more than 1 pod, this is not the last pod so we can just let the pod terminate.
	return apiutils.RemoveFinalizerFromPod(ctx, r.client, pod, metadata.GCPSAFinalizer)
}

func (r *Reconciler) HandlePodUpdate(ctx context.Context, pod corev1.Pod) (ctrl.Result, error) {
	if !r.podHasGCPLabels(pod) {
		return ctrl.Result{}, nil
	}

	// Add a finalizer label to the pod to block deletion until cleanup is complete
	updatedPod := pod.DeepCopy()
	if controllerutil.AddFinalizer(updatedPod, metadata.GCPSAFinalizer) {
		err := r.client.Patch(ctx, updatedPod, client.MergeFrom(&pod))
		if err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
	}

	// Get pod service account
	var serviceAccount corev1.ServiceAccount
	err := r.client.Get(ctx, types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      pod.Spec.ServiceAccountName,
	}, &serviceAccount)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err)
	}

	// Skip if the service account is already labeled
	_, labeled := serviceAccount.Labels[metadata.OtterizeGCPServiceAccountLabel]
	if labeled {
		return ctrl.Result{}, nil
	}

	logrus.Debugf("Tagging the pod (%s) service account (%s) for GCP workload identity: ", pod.Name, serviceAccount.Name)
	updatedServiceAccount := serviceAccount.DeepCopy()
	if updatedServiceAccount.Annotations == nil {
		updatedServiceAccount.Annotations = make(map[string]string)
	}
	if updatedServiceAccount.Labels == nil {
		updatedServiceAccount.Labels = make(map[string]string)
	}

	// Tag the service account with the required labels and annotations
	updatedServiceAccount.Annotations[k8s.WorkloadIdentityAnnotation] = metadata.GCPWorkloadIdentityNotSet
	updatedServiceAccount.Labels[metadata.OtterizeGCPServiceAccountLabel] = metadata.OtterizeServiceAccountHasPodsValue
	err = r.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err)
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) podHasGCPLabels(pod corev1.Pod) bool {
	if pod.Labels == nil {
		return false
	}
	_, labelExists := pod.Labels[metadata.CreateGCPRoleLabel]
	return labelExists
}
