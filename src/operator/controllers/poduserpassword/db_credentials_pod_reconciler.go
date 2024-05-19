package poduserpassword

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/aidarkhanov/nanoid"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	otterizev1alpha3 "github.com/otterize/intents-operator/src/operator/api/v1alpha3"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator/mysql"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator/postgres"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/otterize/intents-operator/src/shared/serviceidresolver"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"strings"
	"time"
)

const (
	ReasonEnsuredPodUserAndPassword        = "EnsuredPodUserAndPassword"
	ReasonEnsuringPodUserAndPasswordFailed = "EnsuringPodUserAndPasswordFailed"
	ReasonMissingDatabaseServerConfig      = "MissingDatabaseServerConfig"
	ReasonPodOwnerResolutionFailed         = "PodOwnerResolutionFailed"
)

const (
	DefaultCredentialsAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	DefaultCredentialsLen      = 16
	RefreshSecretsLoopTick     = time.Minute
	OtterizeManagedSecretLabel = "credentials-operator.otterize.com/managed-secret"
)

type Reconciler struct {
	client            client.Client
	scheme            *runtime.Scheme
	recorder          record.EventRecorder
	serviceIdResolver *serviceidresolver.Resolver
}

func NewReconciler(client client.Client, scheme *runtime.Scheme, eventRecorder record.EventRecorder, serviceIdResolver *serviceidresolver.Resolver) *Reconciler {
	return &Reconciler{
		client:            client,
		scheme:            scheme,
		serviceIdResolver: serviceIdResolver,
		recorder:          eventRecorder,
	}
}

func (e *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&v1.Pod{}).
		Complete(e)
}

func (e *Reconciler) shouldHandleCredentialsForPod(pod v1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}

	return hasDatabaseUsernameAnnotation(pod) && hasUserAndPasswordSecretAnnotation(pod)
}

func hasUserAndPasswordSecretAnnotation(pod v1.Pod) bool {
	_, ok := pod.Annotations[metadata.UserAndPasswordSecretNameAnnotation]
	return ok
}

func hasDatabaseUsernameAnnotation(pod v1.Pod) bool {
	_, ok := pod.Annotations[databaseconfigurator.DatabaseUsernameAnnotation]
	return ok
}

func (e *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod v1.Pod
	err := e.client.Get(ctx, req.NamespacedName, &pod)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}
	if !pod.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if !e.shouldHandleCredentialsForPod(pod) {
		return ctrl.Result{}, nil
	}

	logrus.Debug("Ensuring user-password credentials secrets for pod")
	err, password := e.ensurePodUserAndPasswordSecret(ctx, &pod, pod.Annotations[metadata.UserAndPasswordSecretNameAnnotation])
	if err != nil {
		e.recorder.Eventf(&pod, v1.EventTypeWarning, ReasonEnsuringPodUserAndPasswordFailed, "Failed to ensure user-password credentials secret: %s", err.Error())
		return ctrl.Result{}, errors.Wrap(err)
	}

	logrus.Debug("Validating password for all databases")
	err = e.ensurePasswordInDatabases(ctx, pod, password)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err)
	}
	e.recorder.Event(&pod, v1.EventTypeNormal, ReasonEnsuredPodUserAndPassword, "Ensured user-password credentials in specified secret")
	return ctrl.Result{}, nil
}

func (e *Reconciler) ensurePodUserAndPasswordSecret(ctx context.Context, pod *v1.Pod, secretName string) (error, string) {
	log := logrus.WithFields(logrus.Fields{"pod": pod.Name, "namespace": pod.Namespace})
	secret := v1.Secret{}
	err := e.client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: secretName}, &secret)
	if apierrors.IsNotFound(err) {
		log.Debug("Creating user-password credentials secret for pod")
		password, err := createServicePassword()
		if err != nil {
			return errors.Wrap(err), ""
		}

		databaseUsername := pod.Annotations[databaseconfigurator.DatabaseUsernameAnnotation]

		secret := buildUserAndPasswordCredentialsSecret(secretName, pod.Namespace, databaseUsername, password)
		log.WithField("secret", secretName).Debug("Creating new secret with user-password credentials")
		if err := e.client.Create(ctx, secret); err != nil {
			return errors.Wrap(err), ""
		}
		return nil, password
	}

	if err != nil {
		return errors.Wrap(err), ""
	}
	log.Debug("Secret exists, nothing to do")
	return nil, string(secret.Data["password"])
}

func (e *Reconciler) ensurePasswordInDatabases(ctx context.Context, pod v1.Pod, password string) error {
	databases := strings.Split(pod.Annotations[databaseconfigurator.DatabaseAccessAnnotation], ",")
	username := pod.Annotations[databaseconfigurator.DatabaseUsernameAnnotation]
	pgServerConfigs := otterizev1alpha3.PostgreSQLServerConfigList{}
	err := e.client.List(ctx, &pgServerConfigs)
	if err != nil {
		return errors.Wrap(err)
	}
	mysqlServerConfigs := otterizev1alpha3.MySQLServerConfigList{}
	err = e.client.List(ctx, &mysqlServerConfigs)
	if err != nil {
		return errors.Wrap(err)
	}

	for _, database := range databases {
		var dbconfigurator databaseconfigurator.DatabaseConfigurator
		mysqlConf, found := lo.Find(mysqlServerConfigs.Items, func(config otterizev1alpha3.MySQLServerConfig) bool {
			return config.Name == database
		})
		if found {
			dbconfigurator, err = mysql.NewMySQLConfigurator(ctx, mysqlConf.Spec)
			if err != nil {
				return errors.Wrap(err)
			}
			err = dbconfigurator.AlterUserPassword(ctx, username, password)
			if err != nil {
				return errors.Wrap(err)
			}
			return nil
		}

		pgServerConf, found := lo.Find(pgServerConfigs.Items, func(config otterizev1alpha3.PostgreSQLServerConfig) bool {
			return config.Name == database
		})
		if found {
			dbconfigurator, err = postgres.NewPostgresConfigurator(ctx, pgServerConf.Spec)
			if err != nil {
				return errors.Wrap(err)
			}
			err = dbconfigurator.AlterUserPassword(ctx, username, password)
			if err != nil {
				return errors.Wrap(err)
			}
			return nil
		}
		// We can only reach here if a server config was deleted after the intents operator updated the annotation on the pod
		// TODO: Log error and continue instead ?
		return errors.Wrap(fmt.Errorf("no matching server config found for database %s", database))
	}
	return nil
}

func (e *Reconciler) RotateSecretsLoop(ctx context.Context) {
	refreshSecretsTicker := time.NewTicker(RefreshSecretsLoopTick)
	for {
		select {
		case <-refreshSecretsTicker.C:
			go func() {
				err := e.RotateSecrets(ctx)
				if err != nil {
					logrus.WithError(err).Error("failed refreshing TLS secrets")
				}
			}()
		case <-ctx.Done():
			return
		}
	}
}

func (e *Reconciler) RotateSecrets(ctx context.Context) error {
	otterizeSecrets := v1.SecretList{}
	if err := e.client.List(ctx, &otterizeSecrets, &client.MatchingLabels{OtterizeManagedSecretLabel: "true"}); err != nil {
		return errors.Wrap(err)
	}
	secretsNeedingRefresh := lo.Filter(otterizeSecrets.Items, func(secret v1.Secret) bool {

	})
	for _, secret := range otterizeSecrets.Items {

	}
}

func buildUserAndPasswordCredentialsSecret(name, namespace, pgUsername, password string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{OtterizeManagedSecretLabel: "true"},
		},
		Data: map[string][]byte{
			"username": []byte(pgUsername),
			"password": []byte(password),
		},
		Type: v1.SecretTypeOpaque,
	}
}

func createServicePassword() (string, error) {
	password, err := nanoid.Generate(DefaultCredentialsAlphabet, DefaultCredentialsLen)
	if err != nil {
		return "", errors.Wrap(err)
	}
	salt, err := nanoid.Generate(DefaultCredentialsAlphabet, 8)
	if err != nil {
		return "", errors.Wrap(err)
	}

	dk := pbkdf2.Key([]byte(password), []byte(salt), 2048, 16, sha256.New)
	return hex.EncodeToString(dk), nil
}
