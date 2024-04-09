package metadata

// Internal use labels, used by the operator to encode data required for its internal operation.
// These labels are auto-generated and should not be modified by the user.
const (
	// RegisteredServiceNameLabel holds the resolved service name, registered as a SPIRE-server entry selector.
	// See documentation for intents.otterize.com/service-name annotation for information re service name resolution.
	RegisteredServiceNameLabel = "credentials-operator.otterize.com/registered-service-name"

	// SecretTypeLabel is used to label secrets generated by the credentials-operator with their secret type.
	// This is used to detect which secrets are managed by this operator.
	SecretTypeLabel = "credentials-operator.otterize.com/secret-type"

	OtterizeServiceAccountHasPodsValue   = "true"
	OtterizeServiceAccountHasNoPodsValue = "no-pods"
)
