package intents

import (
	"context"
	"fmt"
	"github.com/amit7itz/goset"
	"github.com/jackc/pgx/v5"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	otterizev1alpha3 "github.com/otterize/intents-operator/src/operator/api/v1alpha3"
	"github.com/otterize/intents-operator/src/operator/databaseconfigurator"
	"github.com/otterize/intents-operator/src/shared/clusterid"
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
)

const (
	PGCreateUserStatement databaseconfigurator.SQLSprintfStatement = "CREATE USER %s WITH PASSWORD %s"
)

const (
	ReasonErrorFetchingPostgresServerConfig = "ErrorFetchingPostgresServerConfig"
	ReasonFailedReadingWorkloadPassword     = "FailedReadingWorkloadPassword"
	ReasonFailedCreatingDatabaseUser        = "FailedCreatingDatabaseUser"
)

type Reconciler struct {
	client            client.Client
	scheme            *runtime.Scheme
	recorder          record.EventRecorder
	serviceIdResolver *serviceidresolver.Resolver
	clusterUID        string
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
		Complete(r)
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

	dbNames := extractDBNames(intents)
	if len(dbNames) == 0 {
		return ctrl.Result{}, nil
	}

	for _, databaseName := range dbNames {
		pgServerConf := otterizev1alpha3.PostgreSQLServerConfig{}
		// TODO: Need to list from the entire cluster & match the databaseName. CRD webhook should enforce cluster-wide name uniqueness
		err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: databaseName}, &pgServerConf)
		if err != nil {
			r.recorder.Eventf(&intents, v1.EventTypeWarning,
				ReasonErrorFetchingPostgresServerConfig,
				"Error trying to fetch '%s' PostgresServerConf for client '%s'. Error: %s",
				intents.GetServiceName(), databaseName, err.Error())

			return ctrl.Result{}, errors.Wrap(err)
		}

		pgConfigurator := databaseconfigurator.NewPostgresConfigurator(pgServerConf.Spec, r.client)
		connectionString := pgConfigurator.FormatConnectionString()
		conn, err := pgx.Connect(ctx, connectionString)
		if err != nil {
			pgErr, ok := pgConfigurator.TranslatePostgresConnectionError(err)
			if ok {
				return ctrl.Result{}, errors.Wrap(fmt.Errorf(pgErr))
			}
			return ctrl.Result{}, errors.Wrap(err)
		}
		pgConfigurator.SetConnection(ctx, conn)

		pgUsername, err := r.getPostgresUserForWorkload(ctx, intents.GetServiceName(), intents.Namespace)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err)
		}
		exists, err := pgConfigurator.ValidateUserExists(ctx, pgUsername)
		if err != nil {
			return ctrl.Result{}, errors.Wrap(err)
		}

		if !exists {
			password, err := r.fetchWorkloadPassword(ctx, intents)
			if err != nil {
				r.recorder.Eventf(&intents, v1.EventTypeWarning,
					ReasonFailedReadingWorkloadPassword,
					"Failed reading client %s Postgres password. Error: %s", intents.GetServiceName(), err.Error())
				return ctrl.Result{}, errors.Wrap(err)
			}

			logrus.WithField("username", pgUsername).Info(
				"Username does not exist in database %s, creating it", databaseName)

			err = r.createPostgresUserForWorkload(ctx, pgConfigurator, pgUsername, password)
			if err != nil {
				r.recorder.Eventf(&intents, v1.EventTypeWarning, ReasonFailedCreatingDatabaseUser,
					"Failed creating database user. Error: %s", err.Error())
				return ctrl.Result{}, errors.Wrap(err)
			}

			logrus.Info("User created successfully")
		}
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) createPostgresUserForWorkload(
	ctx context.Context,
	pgConfigurator *databaseconfigurator.PostgresConfigurator,
	pgUsername string,
	password string) error {

	batch := pgx.Batch{}
	stmt, err := PGCreateUserStatement.PrepareSanitized(pgx.Identifier{pgUsername}, databaseconfigurator.NonUserInputString(password))
	if err != nil {
		return errors.Wrap(err)
	}
	batch.Queue(stmt)
	batchResults := pgConfigurator.Conn.SendBatch(ctx, &batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := batchResults.Exec(); err != nil {
			return errors.Wrap(err)
		}
	}
	if err := batchResults.Close(); err != nil {
		logrus.Errorf("Failed closing batch results")
	}

	return nil
}

func (r *Reconciler) getPostgresUserForWorkload(ctx context.Context, client, namespace string) (string, error) {
	clusterUID, err := clusterid.GetClusterUID(ctx)
	if err != nil {
		return "", errors.Wrap(err)
	}

	return databaseconfigurator.BuildPostgresUsername(clusterUID, client, namespace), nil
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

func extractDBNames(intents otterizev1alpha3.ClientIntents) []string {
	dbNames := goset.Set[string]{}
	for _, intent := range intents.GetCallsList() {
		if intent.Type != otterizev1alpha3.IntentTypeDatabase {
			continue
		}
		for _, res := range intent.DatabaseResources {
			dbNames.Add(res.DatabaseName)
		}
	}

	return dbNames.Items()
}
