package poduserpassword

import (
	"context"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	otterizev1alpha3 "github.com/otterize/intents-operator/src/operator/api/v1alpha3"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator/mysql"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator/postgres"
	"github.com/otterize/intents-operator/src/shared/errors"
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
	"strings"
)

const (
	ReasonEnsuredPodUserAndPassword        = "EnsuredPodUserAndPassword"
	ReasonEnsuringPodUserAndPasswordFailed = "EnsuringPodUserAndPasswordFailed"
	ReasonEnsuringDatabasePasswordFailed   = "EnsuringDatabasePasswordFailed"
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
	return pod.Annotations != nil && hasDatabaseUsernameAnnotation(pod) && hasUserAndPasswordSecretAnnotation(pod)
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

	logrus.Debug("Validating password in all databases")
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
		password, err := databaseconfigurator.GenerateRandomPassword()
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
		dbconfigurator, found, err := e.createDBConfigurator(ctx, database, mysqlServerConfigs.Items, pgServerConfigs.Items)
		if err != nil {
			return errors.Wrap(err)
		}
		if !found {
			logrus.Warningf("Missing database server config for db: %s", database)
			e.recorder.Eventf(&pod, v1.EventTypeWarning, ReasonEnsuringDatabasePasswordFailed,
				"Failed to ensure database password in %s. Missing database server config", database)
			continue
		}
		defer dbconfigurator.CloseConnection(ctx)
		if err := dbconfigurator.AlterUserPassword(ctx, username, password); err != nil {
			return errors.Wrap(err)
		}
	}

	return nil
}

func (e *Reconciler) createDBConfigurator(
	ctx context.Context,
	database string,
	mysqlServerConfigs []otterizev1alpha3.MySQLServerConfig,
	pgServerConfigs []otterizev1alpha3.PostgreSQLServerConfig) (databaseconfigurator.DatabaseConfigurator, bool, error) {

	mysqlConf, found := lo.Find(mysqlServerConfigs, func(config otterizev1alpha3.MySQLServerConfig) bool {
		return config.Name == database
	})
	if found {
		dbconfigurator, err := mysql.NewMySQLConfigurator(ctx, mysqlConf.Spec)
		if err != nil {
			return nil, false, errors.Wrap(err)
		}
		return dbconfigurator, true, nil
	}

	pgServerConf, found := lo.Find(pgServerConfigs, func(config otterizev1alpha3.PostgreSQLServerConfig) bool {
		return config.Name == database
	})
	if found {
		dbconfigurator, err := postgres.NewPostgresConfigurator(ctx, pgServerConf.Spec)
		if err != nil {
			return nil, false, errors.Wrap(err)
		}
		return dbconfigurator, true, nil
	}

	return nil, false, nil
}

func buildUserAndPasswordCredentialsSecret(name, namespace, pgUsername, password string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"username": []byte(pgUsername),
			"password": []byte(password),
		},
		Type: v1.SecretTypeOpaque,
	}
}
