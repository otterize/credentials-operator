package controllers

import (
	"context"
	"github.com/otterize/spifferize/src/operator/secrets"
	spire_client "github.com/otterize/spifferize/src/spire-client"
	"github.com/otterize/spifferize/src/spire-client/entries"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

const (
	refreshSecretsLoopTick = time.Minute
	ServiceNameLabel       = "otterize/service-name"
	TLSSecretNameLabel     = "otterize/tls-secret-name"
)

// PodReconciler reconciles a Pod object
type PodReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	SpireClient     spire_client.ServerClient
	EntriesRegistry *entries.Registry
	SecretsManager  *secrets.Manager
}

// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=create;get;list;update;patch

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logrus.WithField("pod", req.NamespacedName)

	// Fetch the Pod from the Kubernetes API.
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			// we'll ignore not-found errors, since they can't be fixed by an immediate
			// requeue (we'll need to wait for a new notification), and we can get them
			// on deleted requests.
			return ctrl.Result{}, nil
		}
		log.WithError(err).Error("unable to fetch Pod")
		return ctrl.Result{}, err
	}

	// Add spire-server entry for pod
	if pod.Labels == nil || pod.Labels[ServiceNameLabel] == "" {
		log.Info("no update required - service name label not found")
		return ctrl.Result{}, nil
	}

	serviceName := pod.Labels[ServiceNameLabel]
	spiffeID, err := r.EntriesRegistry.RegisterK8SPodEntry(ctx, pod.Namespace, ServiceNameLabel, serviceName)
	if err != nil {
		log.WithError(err).Error("failed registering SPIRE entry for pod")
		return ctrl.Result{}, err
	}

	secretName := pod.Labels[TLSSecretNameLabel]
	if secretName != "" {
		if err := r.SecretsManager.EnsureTLSSecret(ctx, pod.Namespace, secretName, serviceName, spiffeID); err != nil {
			log.WithError(err).Error("failed creating TLS secret")
			return ctrl.Result{}, err
		}
	} else {
		log.Infof("skipping secrets creation - %s label not found", TLSSecretNameLabel)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

func (r *PodReconciler) RefreshSecretsLoop() {
	ticker := time.NewTicker(refreshSecretsLoopTick)

	for {
		select {
		case <-ticker.C:
			_ = r.SecretsManager.RefreshTLSSecrets(context.Background())
		}
	}
}
