package intents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/aidarkhanov/nanoid"
	"github.com/amit7itz/goset"
	"github.com/jackc/pgx/v5"
	"github.com/otterize/credentials-operator/src/controllers/poduserpassword"
	otterizev1alpha3 "github.com/otterize/intents-operator/src/operator/api/v1alpha3"
	"github.com/otterize/intents-operator/src/operator/databaseconfigurator"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/otterize/intents-operator/src/shared/serviceidresolver"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/pbkdf2"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

const (
	PGCreateUserStatement databaseconfigurator.SQLSprintfStatement = "CREATE USER %s WITH PASSWORD %s"
	PGDefaultDatabase
	OtterizeClusterUIDResourceName = "otterize-cluster-uid"
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
		err := r.client.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: databaseName}, &pgServerConf)
		if err != nil {
			r.recorder.Eventf(&intents, v1.EventTypeWarning,
				"Failed validating user credentials for %s with error:", intents.GetServiceName(), err.Error())
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
			logrus.WithField("username", pgUsername).Info(
				"Username does not exist in database %s, creating it", databaseName)
			r.createPostgresUserForWorkload(ctx, pgUsername, pgConfigurator)

		}

	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) createPostgresUserForWorkload(
	ctx context.Context,
	pgUsername string,
	pgConfigurator *databaseconfigurator.PostgresConfigurator) error {

	batch := pgx.Batch{}
	password, err := createServicePassword()
	if err != nil {
		return errors.Wrap(err)
	}
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
	clusterUID, err := r.getClusterUID(ctx)
	if err != nil {
		return "", errors.Wrap(err)
	}

	return databaseconfigurator.BuildPostgresUsername(clusterUID, client, namespace), nil
}

// Fetches cluster ID from the config map created in the Otterize namespace (created by the intents operator)
func (r *Reconciler) getClusterUID(ctx context.Context) (string, error) {
	if r.clusterUID != "" {
		return r.clusterUID, nil
	}

	podNamespace := os.Getenv("POD_NAMESPACE")
	cm := v1.ConfigMap{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: podNamespace, Name: OtterizeClusterUIDResourceName}, &cm)
	if err != nil {
		return "", errors.Wrap(err)
	}

	clusterUID, ok := cm.Data["clusteruid"]
	if !ok || clusterUID == "" {
		return "", errors.Wrap(fmt.Errorf("invalid cluster UID found in %s config map", OtterizeClusterUIDResourceName))
	}

	r.clusterUID = clusterUID
	return clusterUID, nil
}

func createServicePassword() (string, error) {
	password, err := nanoid.Generate(poduserpassword.DefaultCredentialsAlphabet, poduserpassword.DefaultCredentialsLen)
	if err != nil {
		return "", err
	}
	salt, err := nanoid.Generate(poduserpassword.DefaultCredentialsAlphabet, 8)
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), []byte(salt), 2048, 16, sha256.New)
	return hex.EncodeToString(dk), nil
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
