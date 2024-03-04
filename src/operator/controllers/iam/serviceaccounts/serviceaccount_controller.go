package serviceaccount

import (
	"context"
	"fmt"
	"github.com/otterize/credentials-operator/src/controllers/iam"
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

type ServiceAccountReconciler struct {
	client.Client
	agents                           []iam.IAMCredentialsAgent
	markRolesAsUnusedInsteadOfDelete bool
}

func NewServiceAccountReconciler(client client.Client, agents []iam.IAMCredentialsAgent, markRolesAsUnusedInsteadOfDelete bool) *ServiceAccountReconciler {
	return &ServiceAccountReconciler{
		Client:                           client,
		agents:                           agents,
		markRolesAsUnusedInsteadOfDelete: markRolesAsUnusedInsteadOfDelete,
	}
}

func (r *ServiceAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&corev1.ServiceAccount{}).
		Complete(r)
}

func (r *ServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": req.Name, "namespace": req.Namespace})

	serviceAccount := corev1.ServiceAccount{}

	err := r.Get(ctx, req.NamespacedName, &serviceAccount)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	value, ok := getLabelValue(&serviceAccount, metadata.OtterizeServiceAccountLabel)
	if !ok {
		logger.Debug("serviceAccount not labeled with credentials-operator.otterize.com/service-account, skipping")
		return ctrl.Result{}, nil
	}

	isReferencedByPods := value == metadata.OtterizeServiceAccountHasPodsValue

	// Perform cleanup if the service account is being deleted or no longer referenced by pods
	if serviceAccount.DeletionTimestamp != nil || !isReferencedByPods {
		return r.HandleServiceCleanup(ctx, serviceAccount)
	}

	return r.HandleServiceUpdate(ctx, serviceAccount)
}

func getLabelValue(serviceAccount *corev1.ServiceAccount, label string) (string, bool) {
	if serviceAccount.Labels == nil {
		return "", false
	}
	value, ok := serviceAccount.Labels[label]
	return value, ok
}

func isManagedByAgent(serviceAccount *corev1.ServiceAccount, agent iam.IAMCredentialsAgent) bool {
	value, ok := getLabelValue(serviceAccount, agent.ServiceManagedByLabel())
	return ok && value == "true"
}

func (r *ServiceAccountReconciler) HandleServiceCleanup(ctx context.Context, serviceAccount corev1.ServiceAccount) (ctrl.Result, error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})
	for _, agent := range r.agents {
		if !isManagedByAgent(&serviceAccount, agent) {
			logger.WithField("label", agent.ServiceManagedByLabel()).Debug("serviceAccount not managed by agent, skipping")
			continue
		}
		if err := agent.DeleteServiceIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to remove service account: %w", err)
		}
	}

	if serviceAccount.DeletionTimestamp != nil {
		updatedServiceAccount := serviceAccount.DeepCopy()
		if controllerutil.RemoveFinalizer(updatedServiceAccount, metadata.IAMRoleFinalizer) {
			err := r.Client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
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

func (r *ServiceAccountReconciler) HandleServiceUpdate(ctx context.Context, serviceAccount corev1.ServiceAccount) (ctrl.Result, error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	// Add a finalizer label to the service account to block deletion until cleanup is complete
	updatedServiceAccount := serviceAccount.DeepCopy()
	if controllerutil.AddFinalizer(updatedServiceAccount, metadata.IAMRoleFinalizer) {
		err := r.Client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
		if err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
	}

	hasUpdates := false
	for _, agent := range r.agents {
		if !isManagedByAgent(&serviceAccount, agent) {
			logger.WithField("label", agent.ServiceManagedByLabel()).Debug("serviceAccount not managed by agent, skipping")
			continue
		}

		updated, requeue, err := agent.ReconcileServiceIAMRole(ctx, updatedServiceAccount, r.shouldUseSoftDeleteStrategy(&serviceAccount))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to reconcile service account: %w", err)
		}
		if requeue {
			return ctrl.Result{Requeue: true}, nil
		}
		hasUpdates = hasUpdates || updated
	}

	if !hasUpdates {
		return ctrl.Result{}, nil
	}

	if err := r.Client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount)); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	return ctrl.Result{}, nil
}

func (r *ServiceAccountReconciler) shouldUseSoftDeleteStrategy(serviceAccount *corev1.ServiceAccount) bool {
	if r.markRolesAsUnusedInsteadOfDelete {
		return true
	}
	if serviceAccount.Labels == nil {
		return false
	}

	softDeleteValue, shouldSoftDelete := serviceAccount.Labels[metadata.OtterizeAWSUseSoftDeleteKey]
	return shouldSoftDelete && softDeleteValue == metadata.OtterizeAWSUseSoftDeleteValue
}
