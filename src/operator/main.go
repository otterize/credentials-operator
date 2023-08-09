/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/bombsimon/logrusr/v3"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/otterize/intents-operator/src/shared/serviceidresolver"
	"github.com/otterize/spire-integration-operator/src/controllers"
	"github.com/otterize/spire-integration-operator/src/controllers/certificates/otterizecertgen"
	"github.com/otterize/spire-integration-operator/src/controllers/certificates/spirecertgen"
	"github.com/otterize/spire-integration-operator/src/controllers/certmanageradapter"
	"github.com/otterize/spire-integration-operator/src/controllers/otterizeclient"
	"github.com/otterize/spire-integration-operator/src/controllers/secrets"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/bundles"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/entries"
	"github.com/otterize/spire-integration-operator/src/controllers/spireclient/svids"
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
	utilruntime.Must(certmanager.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func initSpireClient(ctx context.Context, spireServerAddr string) (spireclient.ServerClient, error) {
	// fetch Certificate & bundle through spire-agent API
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath), workloadapi.WithLogger(logrus.StandardLogger())))
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

//type CertProvider uint
//
//var CertProviderEnum = flagenum.Enum{
//	"spire":        CertProvider(0),
//	"cloud":        CertProvider(1),
//	"cert-manager": CertProvider(2),
//}
//
//func (val *CertProvider) Set(v string) error {
//	if v == "" {
//		// default value
//		return CertProviderEnum.FlagSet(val, "spire")
//	}
//	return CertProviderEnum.FlagSet(val, v)
//}
//
//func (val *CertProvider) String() string {
//	return CertProviderEnum.FlagString(*val)
//}

const (
	ProviderSpire       = "spire"
	ProviderCloud       = "cloud"
	ProviderCertManager = "cert-manager"
)

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var spireServerAddr string
	var certProvider string
	var secretsManager controllers.SecretsManager
	var workloadRegistry controllers.WorkloadRegistry
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":7071", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":7072", "The address the probe endpoint binds to.")
	flag.StringVar(&spireServerAddr, "spire-server-address", "spire-server.spire:8081", "SPIRE server API address.")
	flag.StringVar(&certProvider, "cert-provider", "cert-manager", fmt.Sprintf("Certificate generation provider (%s, %s, %s)", ProviderSpire, ProviderCloud, ProviderCertManager))
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

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

	serviceIdResolver := serviceidresolver.NewResolver(mgr.GetClient())
	eventRecorder := mgr.GetEventRecorderFor("spire-integration-operator")

	if certProvider == ProviderCloud {
		otterizeCloudClient, err := otterizeclient.NewCloudClient(ctx)
		if err != nil {
			logrus.WithError(err).Error("failed to connect to otterize cloud")
			os.Exit(1)
		}
		workloadRegistry = otterizeCloudClient
		otterizeclient.PeriodicallyReportConnectionToCloud(otterizeCloudClient)
		otterizeCertManager := otterizecertgen.NewOtterizeCertificateGenerator(otterizeCloudClient)
		secretsManager = secrets.NewSecretManager(mgr.GetClient(), otterizeCertManager, serviceIdResolver, eventRecorder)
	} else if certProvider == ProviderSpire {
		spireClient, err := initSpireClient(ctx, spireServerAddr)
		if err != nil {
			logrus.WithError(err).Error("failed to connect to spire server")
			os.Exit(1)
		}
		defer spireClient.Close()

		bundlesStore := bundles.NewBundlesStore(spireClient)
		svidsStore := svids.NewSVIDsStore(spireClient)
		certGenerator := spirecertgen.NewSpireCertificateDataGenerator(bundlesStore, svidsStore)
		secretsManager = secrets.NewSecretManager(mgr.GetClient(), certGenerator, serviceIdResolver, eventRecorder)
		workloadRegistry = entries.NewSpireRegistry(spireClient)
	} else if certProvider == ProviderCertManager {
		certManagerAdapter := certmanageradapter.NewCertManagerSecretsAdapter(mgr.GetClient(), serviceIdResolver, eventRecorder, "ca-issuer")
		secretsManager = certManagerAdapter
		workloadRegistry = certManagerAdapter
	} else {
		// TODO: Check before
		logrus.Error("unsupported certificate provider")
		os.Exit(1)
	}

	podReconciler := controllers.NewPodReconciler(mgr.GetClient(), mgr.GetScheme(), workloadRegistry, secretsManager,
		serviceIdResolver, eventRecorder, certProvider == ProviderCloud)

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

	go podReconciler.MaintenanceLoop(ctx)
	if err := mgr.Start(ctx); err != nil {
		logrus.WithError(err).Error("problem running manager")
		os.Exit(1)
	}
}
