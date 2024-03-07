package operatorconfig

import (
	"fmt"
	"github.com/otterize/intents-operator/src/shared"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"strings"
)

const (
	TelemetryErrorsAPIKeyKey                 = "telemetry-errors-api-key"
	TelemetryErrorsAPIKeyDefault             = "20b1b74678347375fedfdba65171acb2"
	AWSRolesAnywhereTrustAnchorARNKey        = "trust-anchor-arn"
	AWSRolesAnywhereSPIFFETrustDomainKey     = "spiffe-trust-domain"
	AWSRolesAnywhereClusterName              = "roles-anywhere-cluster-name"
	EnableAWSServiceAccountManagementKey     = "enable-aws-serviceaccount-management"
	EnableAWSServiceAccountManagementDefault = false
	EnableAWSRolesAnywhereKey                = "enable-aws-iam-rolesanywhere"
	EnableAWSRolesAnywhereDefault            = false
	MetricsAddrKey                           = "metrics-bind-address"
	MetricsAddrDefault                       = ":7071"
	ProbeAddrKey                             = "health-probe-bind-address"
	ProbeAddrDefault                         = ":7072"
	SpireServerAddrKey                       = "spire-server-address"
	SpireServerAddrDefault                   = "spire-server.spire:8081"
	CertProviderKey                          = "certificate-provider"
	CertProviderDefault                      = CertProviderNone
	CertManagerIssuerKey                     = "cert-manager-issuer"
	CertManagerIssuerDefault                 = "ca-issuer"
	SelfSignedCertKey                        = "self-signed-cert"
	SelfSignedCertDefault                    = true
	CertManagerUseClustierIssuerKey          = "cert-manager-use-cluster-issuer"
	CertManagerUseClusterIssuerDefault       = false
	UseCertManagerApproverKey                = "cert-manager-approve-requests"
	UseCertManagerApproverDefault            = false
	AWSUseSoftDeleteStrategyKey              = "aws-use-soft-delete"
	AWSUseSoftDeleteStrategyDefault          = false
	DebugKey                                 = "debug"
	DebugDefault                             = false
	EnableLeaderElectionKey                  = "leader-elect"
	EnableLeaderElectionDefault              = false
	EnvPrefix                                = "OTTERIZE"
)

const (
	CertProviderSPIRE       = "spire"
	CertProviderCloud       = "otterize-cloud"
	CertProviderCertManager = "cert-manager"
	CertProviderNone        = "none"
)

func init() {
	viper.SetDefault(EnableAWSServiceAccountManagementKey, EnableAWSServiceAccountManagementDefault)
	viper.SetDefault(EnableAWSRolesAnywhereKey, EnableAWSRolesAnywhereDefault)
	viper.SetDefault(TelemetryErrorsAPIKeyKey, TelemetryErrorsAPIKeyDefault)
	viper.SetDefault(MetricsAddrKey, MetricsAddrDefault)
	viper.SetDefault(ProbeAddrKey, ProbeAddrDefault)
	viper.SetDefault(SpireServerAddrKey, SpireServerAddrDefault)
	viper.SetDefault(CertProviderKey, CertProviderDefault)
	viper.SetDefault(SelfSignedCertKey, SelfSignedCertDefault)
	viper.SetDefault(EnableLeaderElectionKey, EnableLeaderElectionDefault)
	viper.SetDefault(CertManagerIssuerKey, CertManagerIssuerDefault)
	viper.SetDefault(CertManagerUseClustierIssuerKey, CertManagerUseClusterIssuerDefault)
	viper.SetDefault(UseCertManagerApproverKey, UseCertManagerApproverDefault)
	viper.SetDefault(AWSUseSoftDeleteStrategyKey, AWSUseSoftDeleteStrategyDefault)
	viper.SetDefault(DebugKey, DebugDefault)
	viper.SetEnvPrefix(EnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// CLI flags for backwards compatibility. New flags should only be added to environment variables.
	pflag.String(MetricsAddrKey, MetricsAddrDefault, "The address the metric endpoint binds to.")

	pflag.String(ProbeAddrKey, ProbeAddrDefault, "The address the probe endpoint binds to.")
	pflag.String(SpireServerAddrKey, SpireServerAddrDefault, "SPIRE server API address.")
	pflag.String(CertProviderKey, CertProviderDefault, fmt.Sprintf("Certificate generation provider"))
	pflag.String(CertManagerIssuerKey, CertManagerIssuerDefault, "Name of the Issuer to be used by cert-manager to sign certificates")
	pflag.Bool(SelfSignedCertKey, SelfSignedCertDefault, "Whether to generate and update a self-signed cert for Webhooks")
	pflag.Bool(CertManagerUseClustierIssuerKey, CertManagerUseClusterIssuerDefault, "Use ClusterIssuer instead of a (namespace bound) Issuer")
	pflag.Bool(UseCertManagerApproverKey, UseCertManagerApproverDefault, "Make credentials-operator approve its own CertificateRequests")
	pflag.Bool(EnableAWSServiceAccountManagementKey, EnableAWSServiceAccountManagementDefault, "Create and bind ServiceAccounts to AWS IAM roles")
	pflag.Bool(AWSUseSoftDeleteStrategyKey, AWSUseSoftDeleteStrategyDefault, "Mark AWS roles and policies as deleted instead of actually deleting them")
	pflag.Bool(DebugKey, DebugDefault, "Enable debug logging")

	pflag.Bool(EnableLeaderElectionKey, EnableLeaderElectionDefault,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	pflag.Parse()

	shared.Must(viper.BindPFlags(pflag.CommandLine))
}
