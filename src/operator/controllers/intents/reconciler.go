package intents

import (
	"context"
	"fmt"
	"github.com/amit7itz/goset"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	otterizev1alpha3 "github.com/otterize/intents-operator/src/operator/api/v1alpha3"
	"github.com/otterize/intents-operator/src/shared/clusterutils"
	"github.com/otterize/intents-operator/src/shared/databaseconfigurator/postgres"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/otterize/intents-operator/src/shared/serviceidresolver"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	ReasonErrorFetchingPostgresServerConfig = "ErrorFetchingPostgresServerConfig"
	ReasonFailedReadingWorkloadPassword     = "FailedReadingWorkloadPassword"
	ReasonFailedCreatingDatabaseUser        = "FailedCreatingDatabaseUser"
	ReasonMissingPostgresServerConfig       = "MissingPostgresServerConfig"
	OtterizeIntentsClientIndexNameField     = "spec.service.name"
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

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{RecoverPanic: lo.ToPtr(true)}).
		For(&otterizev1alpha3.ClientIntents{}).
		Watches(&otterizev1alpha3.PostgreSQLServerConfig{}, handler.EnqueueRequestsFromMapFunc(r.mapPGServerConfToClientIntents)).
		Watches(&v1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToClientIntents)).
		Complete(r)
}

func (r *Reconciler) mapPodToClientIntents(ctx context.Context, obj client.Object) []reconcile.Request {
	requests := make([]reconcile.Request, 0)
	pod := obj.(*v1.Pod)
	if !pod.DeletionTimestamp.IsZero() {
		return requests
	}

	otterizeIdentity, err := r.serviceIdResolver.ResolvePodToServiceIdentity(context.Background(), pod)
	if err != nil {
		logrus.Errorf("Failed resovling Otterize identity for pod %s: %v", pod.Name, err)
	}
	fullClientName := fmt.Sprintf("%s.%s", otterizeIdentity.Name, otterizeIdentity.Namespace)
	logrus.Infof("Enqueueing client intents for client '%s'", fullClientName)

	clientIntentsList := otterizev1alpha3.ClientIntentsList{}
	err = r.client.List(ctx,
		&clientIntentsList,
		&client.MatchingFields{OtterizeIntentsClientIndexNameField: fullClientName},
	)

	if err != nil {
		logrus.Errorf("Failed to list intents for client %s: %v", fullClientName, err)
	}
	for _, clientIntents := range clientIntentsList.Items {
		request := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      clientIntents.Name,
				Namespace: clientIntents.Namespace,
			},
		}
		requests = append(requests, request)
	}

	return requests
}

func (r *Reconciler) mapPGServerConfToClientIntents(ctx context.Context, obj client.Object) []reconcile.Request {
	pgServerConf := obj.(*otterizev1alpha3.PostgreSQLServerConfig)
	logrus.Infof("Enqueueing client intents for PostgreSQLServerConfig change %s", pgServerConf.Name)

	intentsToReconcile := make([]otterizev1alpha3.ClientIntents, 0)
	intentsList := otterizev1alpha3.ClientIntentsList{}
	dbInstanceName := pgServerConf.Name
	err := r.client.List(ctx,
		&intentsList,
		&client.MatchingFields{otterizev1alpha3.OtterizeTargetServerIndexField: dbInstanceName},
	)
	if err != nil {
		logrus.Errorf("Failed to list client intents targeting %s: %v", dbInstanceName, err)
	}
	intentsToReconcile = append(intentsToReconcile, intentsList.Items...)

	requests := make([]reconcile.Request, 0)
	for _, clientIntents := range intentsToReconcile {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      clientIntents.Name,
				Namespace: clientIntents.Namespace,
			},
		})
	}
	return requests
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var intents otterizev1alpha3.ClientIntents
	err := r.client.Get(ctx, req.NamespacedName, &intents)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err)
	}

	dbNames := extractDBInstanceNames(intents)
	if len(dbNames) == 0 {
		return ctrl.Result{}, nil
	}

	pgServerConfigs := otterizev1alpha3.PostgreSQLServerConfigList{}
	err = r.client.List(ctx, &pgServerConfigs)
	if err != nil {
		r.recorder.Eventf(&intents, v1.EventTypeWarning, ReasonErrorFetchingPostgresServerConfig,
			"Error trying to list PostgresServerConfigs. Error: %s", err.Error())
		return ctrl.Result{}, errors.Wrap(err)
	}

	for _, databaseName := range dbNames {
		pgServerConf, err := findMatchingPGServerConfForDBInstance(databaseName, pgServerConfigs)
		if err != nil {
			r.recorder.Eventf(&intents, v1.EventTypeWarning, ReasonMissingPostgresServerConfig,
				"Could not find matching PostgreSQLServerConfig. Error: %s", err.Error())
			return ctrl.Result{}, nil // Not returning error on purpose, missing PGServerConf - record event and move on
		}

		pgConfigurator, err := postgres.NewPostgresConfigurator(ctx, pgServerConf.Spec)
		if err != nil {
			r.recorder.Eventf(&intents, v1.EventTypeWarning, ReasonMissingPostgresServerConfig,
				"Error connecting to PostgreSQL server. Error: %s", err.Error())
			return ctrl.Result{}, errors.Wrap(err)
		}
		err = r.handleDBUserCreation(ctx, intents, pgConfigurator, databaseName)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err)
		}
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) getPostgresUserForWorkload(ctx context.Context, clientName, namespace string) (string, error) {
	clusterUID, err := clusterutils.GetClusterUID(ctx)
	if err != nil {
		return "", errors.Wrap(err)
	}
	username := clusterutils.BuildHashedUsername(clientName, namespace, clusterUID)
	return clusterutils.KubernetesToPostgresName(username), nil
}

func (r *Reconciler) fetchWorkloadPassword(ctx context.Context, clientIntents otterizev1alpha3.ClientIntents) (string, error) {
	pod, err := r.serviceIdResolver.ResolveClientIntentToPod(ctx, clientIntents)
	if err != nil {
		return "", errors.Wrap(err)
	}
	secretName, ok := pod.Annotations[metadata.UserAndPasswordSecretNameAnnotation]
	if !ok {
		return "", errors.Wrap(fmt.Errorf("pods for client %s has no credentials annotation, cannot validate DB user exists", clientIntents.GetServiceName()))
	}
	secret := v1.Secret{}
	err = r.client.Get(ctx, types.NamespacedName{
		Namespace: clientIntents.Namespace,
		Name:      secretName,
	}, &secret)
	if err != nil {
		return "", errors.Wrap(fmt.Errorf("failed reading secret for client %s. Error: %s", clientIntents.GetServiceName(), err.Error()))
	}

	return string(secret.Data["password"]), nil
}

func (r *Reconciler) InitIntentsClientIndices(mgr ctrl.Manager) error {
	err := mgr.GetCache().IndexField(
		context.Background(),
		&otterizev1alpha3.ClientIntents{}, OtterizeIntentsClientIndexNameField,
		func(object client.Object) []string {
			clientIntents := object.(*otterizev1alpha3.ClientIntents)
			return []string{fmt.Sprintf("%s.%s", clientIntents.Spec.Service.Name, clientIntents.Namespace)}
		})
	if err != nil {
		return errors.Wrap(err)
	}

	return nil
}

func (r *Reconciler) InitIntentsDatabaseServerIndices(mgr ctrl.Manager) error {
	err := mgr.GetCache().IndexField(
		context.Background(),
		&otterizev1alpha3.ClientIntents{},
		otterizev1alpha3.OtterizeTargetServerIndexField,
		func(object client.Object) []string {
			var res []string
			intents := object.(*otterizev1alpha3.ClientIntents)
			if intents.Spec == nil {
				return nil
			}
			// Only relevant for database intents for now
			for _, intent := range intents.GetCallsList() {
				if intent.DatabaseResources != nil {
					res = append(res, intent.GetTargetServerName())
				}
			}
			return res
		})
	if err != nil {
		return errors.Wrap(err)
	}
	return nil
}

func (r *Reconciler) handleDBUserCreation(
	ctx context.Context,
	intents otterizev1alpha3.ClientIntents,
	pgConfigurator *postgres.PostgresConfigurator,
	databaseName string) error {

	pgUsername, err := r.getPostgresUserForWorkload(ctx, intents.GetServiceName(), intents.Namespace)
	if err != nil {
		return errors.Wrap(err)
	}
	exists, err := pgConfigurator.ValidateUserExists(ctx, pgUsername)
	if err != nil {
		return errors.Wrap(err)
	}

	if exists {
		return nil
	}

	password, err := r.fetchWorkloadPassword(ctx, intents)
	if err != nil {
		r.recorder.Eventf(&intents, v1.EventTypeWarning,
			ReasonFailedReadingWorkloadPassword,
			"Failed reading client %s Postgres password. Error: %s", intents.GetServiceName(), err.Error())
		return errors.Wrap(err)
	}

	logrus.WithField("username", pgUsername).Infof(
		"Username does not exist in database %s, creating it", databaseName)

	err = pgConfigurator.CreateUser(ctx, pgUsername, password)
	if err != nil {
		r.recorder.Eventf(&intents, v1.EventTypeWarning, ReasonFailedCreatingDatabaseUser,
			"Failed creating database user. Error: %s", err.Error())
		return errors.Wrap(err)
	}
	logrus.Info("User created successfully")
	return nil
}

func extractDBInstanceNames(intents otterizev1alpha3.ClientIntents) []string {
	dbNames := goset.NewSet[string]()
	for _, intent := range intents.GetCallsList() {
		if intent.Type != otterizev1alpha3.IntentTypeDatabase {
			continue
		}
		dbNames.Add(intent.GetTargetServerName())
	}

	return dbNames.Items()
}

func findMatchingPGServerConfForDBInstance(
	databaseInstanceName string,
	pgServerConfigList otterizev1alpha3.PostgreSQLServerConfigList) (*otterizev1alpha3.PostgreSQLServerConfig, error) {

	conf, found := lo.Find(pgServerConfigList.Items, func(conf otterizev1alpha3.PostgreSQLServerConfig) bool {
		return conf.Name == databaseInstanceName
	})

	if !found {
		return nil, errors.Wrap(fmt.Errorf(
			"did not find Postgres server config to match database '%s' in the cluster", databaseInstanceName))
	}

	return &conf, nil

}
