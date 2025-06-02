package awscredentialsagent

import (
	"bytes"
	"context"
	"encoding/json"
	awstypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	rolesanywhereTypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/otterize/credentials-operator/src/shared/apiutils"
	"github.com/otterize/intents-operator/src/shared/awsagent"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	// AWSAgentFinalizer indicates that cleanup on AWS is needed upon termination.
	AWSAgentFinalizer = "credentials-operator.otterize.com/aws-role"

	// AWSOtterizeServiceAccountLabel is used to label service accounts managed by the credentials-operator
	AWSOtterizeServiceAccountLabel = "credentials-operator.otterize.com/aws-service-account-managed"

	// ServiceAccountAWSRoleARNAnnotation is used by EKS (Kubernetes at AWS) to link between service accounts
	// and IAM roles
	ServiceAccountAWSRoleARNAnnotation = "eks.amazonaws.com/role-arn"

	// OtterizeServiceAccountAWSRoleARNAnnotation is used to update a Pod in the mutating webhook with the role ARN
	// so that reinvocation is triggered for the EKS pod identity mutating webhook.
	OtterizeServiceAccountAWSRoleARNAnnotation = "credentials-operator.otterize.com/eks-role-arn"

	// OtterizeAWSAdditionalTrustRelationshipStatementsAnnotation is used to add additional trust relationship statements to the role.
	OtterizeAWSAdditionalTrustRelationshipStatementsAnnotation = "credentials-operator.otterize.com/additional-role-trust-relationship-statements"

	// OtterizeAWSUseSoftDeleteKey is used to mark workloads that should not have their corresponding roles deleted,
	// but should be tagged as deleted instead (aka soft delete strategy).
	OtterizeAWSUseSoftDeleteKey   = "credentials-operator.otterize.com/aws-use-soft-delete"
	OtterizeAWSUseSoftDeleteValue = "true"
)

type Agent struct {
	agent *awsagent.Agent
}

func NewAWSCredentialsAgent(awsAgent *awsagent.Agent) *Agent {
	return &Agent{awsAgent}
}

func (a *Agent) AppliesOnPod(pod *corev1.Pod) bool {
	return a.agent.AppliesOnPod(pod)
}

func (a *Agent) FinalizerName() string {
	return AWSAgentFinalizer
}

func (a *Agent) ServiceAccountLabel() string {
	return AWSOtterizeServiceAccountLabel
}

func (a *Agent) OnPodAdmission(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount, dryRun bool) error {
	logger := logrus.WithFields(logrus.Fields{"pod": pod.Name, "serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	roleArn := a.agent.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
	apiutils.AddAnnotation(serviceAccount, ServiceAccountAWSRoleARNAnnotation, roleArn)
	apiutils.AddAnnotation(serviceAccount, awsagent.ServiceAccountAWSAccountIDAnnotation, a.agent.AccountID)
	apiutils.AddAnnotation(pod, OtterizeServiceAccountAWSRoleARNAnnotation, roleArn)
	additionalStatements, ok := pod.Annotations[OtterizeAWSAdditionalTrustRelationshipStatementsAnnotation]
	if ok {
		var statements []awsagent.StatementEntry
		err := json.Unmarshal([]byte(additionalStatements), &statements)
		if err != nil {
			return errors.Errorf("failed to unmarshal additional trust relationship statements: %w", err)
		}
		logger.WithField("statements", statements).Debug("Adding additional trust relationship statements to role")
		apiutils.AddAnnotation(serviceAccount, OtterizeAWSAdditionalTrustRelationshipStatementsAnnotation, additionalStatements)
	}

	podUseSoftDeleteLabelValue, podUseSoftDeleteLabelExists := pod.Labels[OtterizeAWSUseSoftDeleteKey]
	shouldMarkForSoftDelete := podUseSoftDeleteLabelExists && podUseSoftDeleteLabelValue == OtterizeAWSUseSoftDeleteValue
	logger.Debugf("should mark for soft delete: %v, labels: %v", shouldMarkForSoftDelete, pod.Labels)
	if shouldMarkForSoftDelete {
		logger.Debugf("Add soft-delete label to service account")
		apiutils.AddLabel(serviceAccount, OtterizeAWSUseSoftDeleteKey, OtterizeAWSUseSoftDeleteValue)
	} else {
		apiutils.RemoveLabel(serviceAccount, OtterizeAWSUseSoftDeleteKey)
	}

	if a.agent.RolesAnywhereEnabled {
		// In RolesAnywhere mode, the pod webhook, and not the reconciler, handles the role creation
		if pod.Spec.Volumes == nil {
			pod.Spec.Volumes = make([]corev1.Volume, 0)
		}

		_, role, profile, err := a.reconcileAWSRoleForRolesAnywhere(ctx, serviceAccount, pod, dryRun)
		if err != nil {
			return errors.Errorf("failed reconciling AWS role: %w", err)
		}

		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "spiffe",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   "spiffe.csi.cert-manager.io",
					ReadOnly: lo.ToPtr(true),
					VolumeAttributes: map[string]string{
						"aws.spiffe.csi.cert-manager.io/trust-profile": *profile.ProfileArn,
						"aws.spiffe.csi.cert-manager.io/trust-anchor":  a.agent.TrustAnchorArn,
						"aws.spiffe.csi.cert-manager.io/role":          *role.Arn,
						"aws.spiffe.csi.cert-manager.io/enable":        "true",
					},
				},
			},
		})

		extraVolumeMounts := []corev1.VolumeMount{
			{
				Name:      "spiffe",
				MountPath: "/aws-config",
				ReadOnly:  true,
			},
		}

		extraEnv := []corev1.EnvVar{
			{
				Name:  "AWS_SHARED_CREDENTIALS_FILE",
				Value: "/aws-config/credentials",
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_ENABLED",
				Value: "true",
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_ROLE_ARN",
				Value: *role.Arn,
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_PROFILE_ARN",
				Value: *profile.ProfileArn,
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_TRUST_ANCHOR_ARN",
				Value: a.agent.TrustAnchorArn,
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_PRIVATE_KEY_PATH",
				Value: "/aws-config/tls.key",
			},
			{
				Name:  "AWS_ROLES_ANYWHERE_CERT_PATH",
				Value: "/aws-config/tls.crt",
			},
		}

		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, extraVolumeMounts...)
			pod.Spec.Containers[i].Env = append(pod.Spec.Containers[i].Env, extraEnv...)
		}

	}

	return nil
}

func (a *Agent) reconcileAWSRoleForRolesAnywhere(ctx context.Context, serviceAccount *corev1.ServiceAccount, pod *corev1.Pod, dryRun bool) (updateAnnotation bool, role *awstypes.Role, profile *rolesanywhereTypes.ProfileDetail, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})
	if dryRun {
		return false, &awstypes.Role{
				Arn: lo.ToPtr("dry-run-role-arn"),
			}, &rolesanywhereTypes.ProfileDetail{
				ProfileArn: lo.ToPtr("dry-run-profile-arn"),
			}, nil
	}

	if roleARN, ok := hasAWSAnnotation(serviceAccount); ok {
		generatedRoleARN := a.agent.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
		found, role, err := a.agent.GetOtterizeRole(ctx, serviceAccount.Namespace, serviceAccount.Name)

		// TODO: check if role is missing necessary trust relationship.

		if err != nil {
			return false, nil, nil, errors.Errorf("failed getting AWS role: %w", err)
		}

		foundProfile, profile, err := a.agent.GetOtterizeProfile(ctx, serviceAccount.Namespace, serviceAccount.Name)
		if err != nil {
			return false, nil, nil, errors.Errorf("failed getting AWS profile: %w", err)
		}

		if found && foundProfile {
			if generatedRoleARN != roleARN {
				logger.WithField("arn", *role.Arn).Debug("ServiceAccount AWS role exists, but annotation is misconfigured, should be updated")
				return true, role, profile, nil
			}
			logger.WithField("arn", *role.Arn).Debug("ServiceAccount has matching AWS role")

			return false, role, profile, nil
		}
	}

	additionalTrustRelationshipStatementsTyped, err := a.calculateTrustRelationshipsFromServiceAccount(serviceAccount)
	if err != nil {
		return false, nil, nil, errors.Wrap(err)
	}
	role, err = a.agent.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name, a.shouldUseSoftDeleteStrategy(serviceAccount), additionalTrustRelationshipStatementsTyped)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	profile, err = a.agent.CreateRolesAnywhereProfileForRole(ctx, *role, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating rolesanywhere profile for role: %w", err)
	}
	logger.WithField("arn", *profile.ProfileId).Info("created AWS profile for ServiceAccount")

	return true, role, profile, nil
}

func (a *Agent) OnPodUpdate(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error) {
	return false, false, nil
}

func (a *Agent) calculateTrustRelationshipsFromServiceAccount(serviceAccount *corev1.ServiceAccount) ([]awsagent.StatementEntry, error) {
	additionalTrustRelationshipStatementsTyped := make([]awsagent.StatementEntry, 0)
	additionalTrustRelationshipStatements, ok := serviceAccount.Annotations[OtterizeAWSAdditionalTrustRelationshipStatementsAnnotation]
	if ok {
		dec := json.NewDecoder(bytes.NewReader([]byte(additionalTrustRelationshipStatements)))
		dec.DisallowUnknownFields()
		err := dec.Decode(&additionalTrustRelationshipStatementsTyped)
		if err != nil {
			return nil, errors.Errorf("failed to unmarshal additional trust relationship statements: %w", err)
		}
	}

	return additionalTrustRelationshipStatementsTyped, nil
}

func (a *Agent) OnServiceAccountUpdate(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	roleARN, ok := hasAWSAnnotation(serviceAccount)

	if a.agent.RolesAnywhereEnabled {
		// In RolesAnywhere mode, the SPIFFE pod webhook, and not the reconciler, handles the role creation
		return false, false, nil
	}

	additionalTrustRelationshipStatementsTyped, err := a.calculateTrustRelationshipsFromServiceAccount(serviceAccount)
	if err != nil {
		return false, false, errors.Wrap(err)
	}

	role, err := a.agent.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name, a.shouldUseSoftDeleteStrategy(serviceAccount), additionalTrustRelationshipStatementsTyped)

	if err != nil {
		return false, false, errors.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	// update annotation if it doesn't exist or if it is misconfigured
	shouldUpdateAnnotation := !ok || roleARN != *role.Arn
	if !shouldUpdateAnnotation {
		return false, false, nil
	}

	apiutils.AddAnnotation(serviceAccount, ServiceAccountAWSRoleARNAnnotation, *role.Arn)
	return true, false, nil
}

func (a *Agent) shouldUseSoftDeleteStrategy(serviceAccount *corev1.ServiceAccount) bool {
	if a.agent.MarkRolesAsUnusedInsteadOfDelete {
		return true
	}
	if serviceAccount.Labels == nil {
		return false
	}

	softDeleteValue, shouldSoftDelete := serviceAccount.Labels[OtterizeAWSUseSoftDeleteKey]
	return shouldSoftDelete && softDeleteValue == OtterizeAWSUseSoftDeleteValue
}

func hasAWSAnnotation(serviceAccount *corev1.ServiceAccount) (string, bool) {
	if serviceAccount.Annotations == nil {
		return "", false
	}

	roleARN, ok := serviceAccount.Annotations[ServiceAccountAWSRoleARNAnnotation]
	return roleARN, ok
}

func (a *Agent) OnServiceAccountTermination(ctx context.Context, serviceAccount *corev1.ServiceAccount) error {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	err := a.agent.DeleteOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return errors.Errorf("failed to remove service account: %w", err)
	}

	if a.agent.RolesAnywhereEnabled {
		deleted, err := a.agent.DeleteRolesAnywhereProfileForServiceAccount(ctx, serviceAccount.Namespace, serviceAccount.Name)
		if err != nil {
			return errors.Errorf("failed to remove rolesanywhere profile for service account: %w", err)
		}

		if !deleted {
			logger.Debug("rolesanywhere profile for service account did not exist when deletion was attempted")
		}

		logger.Debug("deleted rolesanywhere profile for service account")
	}

	return nil
}
