package main

import (
	"context"
	"flag"
	"github.com/bombsimon/logrusr/v3"
	"github.com/otterize/spire-integration-operator/src/operator/controllers"
	"github.com/otterize/spire-integration-operator/src/operator/secrets"
	"github.com/otterize/spire-integration-operator/src/spireclient"
	"github.com/otterize/spire-integration-operator/src/spireclient/bundles"
	"github.com/otterize/spire-integration-operator/src/spireclient/entries"
	"github.com/otterize/spire-integration-operator/src/spireclient/svids"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	// +kubebuilder:scaffold:imports
)

var (
	scheme = runtime.NewScheme()
)

const (
	socketPath = "unix:////run/spire/sockets/agent.sock"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func initSpireClient(ctx context.Context, spireServerAddr string) (spireclient.ServerClient, error) {
	// fetch SVID & bundle through spire-agent API
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, err
	}

	serverClient, err := spireclient.NewServerClient(ctx, spireServerAddr, source)
	if err != nil {
		return nil, err
	}
	logrus.WithField("server_address", spireServerAddr).Infof("Successfully connected to SPIRE server")
	return serverClient, nil
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var spireServerAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&spireServerAddr, "spire-server-address", "spire-server.spire:8081", "SPIRE server API address.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	ctrl.SetLogger(logrusr.New(logrus.StandardLogger()))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "spire-integration-operator.otterize.com",
	})
	if err != nil {
		logrus.WithError(err).Error("unable to start manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	spireClient, err := initSpireClient(ctx, spireServerAddr)
	if err != nil {
		logrus.WithError(err).Error("failed to connect to spire server")
		os.Exit(1)
	}
	defer spireClient.Close()

	bundlesStore := bundles.NewBundlesStore(spireClient)
	svidsStore := svids.NewSVIDsStore(spireClient)
	entriesRegistry := entries.NewEntriesRegistry(spireClient)
	secretsManager := secrets.NewSecretsManager(mgr.GetClient(), bundlesStore, svidsStore)

	podReconciler := &controllers.PodReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SpireClient:     spireClient,
		EntriesRegistry: entriesRegistry,
		SecretsManager:  secretsManager,
	}

	if err = podReconciler.SetupWithManager(mgr); err != nil {
		logrus.WithField("controller", "Pod").WithError(err).Error("unable to create controller")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("health", healthz.Ping); err != nil {
		logrus.WithError(err).Error("unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("check", healthz.Ping); err != nil {
		logrus.WithError(err).Error("unable to set up ready check")
		os.Exit(1)
	}

	logrus.Info("starting manager")

	go podReconciler.RefreshSecretsLoop(ctx)
	if err := mgr.Start(ctx); err != nil {
		logrus.WithError(err).Error("problem running manager")
		os.Exit(1)
	}
}
