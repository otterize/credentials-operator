package db_credentials_pod

import (
	"context"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/otterize/credentials-operator/src/controllers/otterizeclient"
	"github.com/otterize/credentials-operator/src/controllers/otterizeclient/otterizegraphql"
	"github.com/otterize/intents-operator/src/shared/serviceidresolver"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sync"
)

const (
	ReasonEnsuredPodDBCredentials        = "EnsuredPodDBCredentials"
	ReasonEnsuringPodDBCredentialsFailed = "EnsuringPodDBCredentialsFailed"
	DatabaseCredentialsSecretNameFmt     = "%s-credentials-for-%s-database"
	ReasonPodOwnerResolutionFailed       = "PodOwnerResolutionFailed"
)

type DatabaseCredentialsAcquirer interface {
	AcquireServiceDatabaseCredentials(ctx context.Context, serviceName, databaseName, namespace string) (*otterizegraphql.DatabaseCredentials, error)
}

type PodDatabaseCredentialsReconciler struct {
	client            client.Client
	scheme            *runtime.Scheme
	recorder          record.EventRecorder
	serviceIdResolver *serviceidresolver.Resolver
	cloudClient       *otterizeclient.CloudClient
	acquirerInitOnce  sync.Once
}

func NewPodDatabaseCredentialsReconciler(client client.Client, scheme *runtime.Scheme, eventRecorder record.EventRecorder, serviceIdResolver *serviceidresolver.Resolver) *PodDatabaseCredentialsReconciler {
	return &PodDatabaseCredentialsReconciler{
		client:            client,
		scheme:            scheme,
		serviceIdResolver: serviceIdResolver,
		recorder:          eventRecorder,
	}
}

func (e *PodDatabaseCredentialsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&v1.Pod{}).
		Complete(e)
}

func (e *PodDatabaseCredentialsReconciler) shouldCreateDBCredentialsSecretsForPod(pod v1.Pod) bool {
	return pod.Annotations != nil && hasDatabaseAccessAnnotation(pod)
}

func hasDatabaseAccessAnnotation(pod v1.Pod) bool {
	_, ok := pod.Annotations[metadata.DBCredentialsSecretNameAnnotation]
	return ok
}

func (e *PodDatabaseCredentialsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod v1.Pod
	err := e.client.Get(ctx, req.NamespacedName, &pod)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !e.shouldCreateDBCredentialsSecretsForPod(pod) {
		return ctrl.Result{}, nil
	}

	logrus.Debug("Ensuring database credentials secrets for pod")
	// resolve pod to otterize service name
	serviceID, err := e.serviceIdResolver.ResolvePodToServiceIdentity(ctx, &pod)
	if err != nil {
		e.recorder.Eventf(&pod, v1.EventTypeWarning, ReasonPodOwnerResolutionFailed, "Could not resolve pod to its owner: %s", err.Error())
		return ctrl.Result{}, err
	}

	err = e.ensurePodDBCredentialsSecrets(ctx, &pod, serviceID.Name, pod.Annotations[metadata.DBCredentialsSecretNameAnnotation])
	if err != nil {
		e.recorder.Eventf(&pod, v1.EventTypeWarning, ReasonEnsuringPodDBCredentialsFailed, "Failed to ensure DB credentials secret: %s", err.Error())
		return ctrl.Result{}, err
	}

	e.recorder.Event(&pod, v1.EventTypeNormal, ReasonEnsuredPodDBCredentials, "Ensured database credentials in specified secret")
	return ctrl.Result{}, nil
}

func (e *PodDatabaseCredentialsReconciler) ensurePodDBCredentialsSecrets(ctx context.Context, pod *v1.Pod, serviceName string, secretName string) error {
	log := logrus.WithFields(logrus.Fields{"pod": pod.Name, "namespace": pod.Namespace})
	err := e.client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: secretName}, &v1.Secret{})
	if apierrors.IsNotFound(err) {
		log.Debug("Creating database credentials secret for pod")
		creds, err := e.cloudClient.AcquireServiceDatabaseCredentials(ctx, serviceName, database, pod.Namespace)
		if err != nil {
			return err
		}

		secret := buildDatabaseCredentialsSecret(secretName, pod.Namespace, creds)
		log.WithField("secret", secretName).Debug("Creating new secret with database credentials")
		if err := e.client.Create(ctx, secret); err != nil {
			return err
		}
	}

	if err != nil {
		return err
	}
	log.Debug("Secret exists, nothing to do")
	return nil
}

func buildDatabaseCredentialsSecret(name, namespace string, creds *otterizegraphql.DatabaseCredentials) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"username": []byte(creds.Username),
			"password": []byte(creds.Password),
		},
		Type: v1.SecretTypeOpaque,
	}
}
