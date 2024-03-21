package awscredentialsagent

import (
	"context"
	"fmt"
	awstypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	rolesanywhereTypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/otterize/intents-operator/src/shared/awsagent"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	// ServiceManagedByAWSAgentLabel is used to mark service accounts that are managed by the AWS agent
	ServiceManagedByAWSAgentLabel = "credentials-operator.otterize.com/managed-by-aws-agent"

	// ServiceAccountAWSRoleARNAnnotation is used by EKS (Kubernetes at AWS) to link between service accounts
	// and IAM roles
	ServiceAccountAWSRoleARNAnnotation = "eks.amazonaws.com/role-arn"

	// OtterizeServiceAccountAWSRoleARNAnnotation is used to update a Pod in the mutating webhook with the role ARN
	// so that reinvocation is triggered for the EKS pod identity mutating webhook.
	OtterizeServiceAccountAWSRoleARNAnnotation = "credentials-operator.otterize.com/eks-role-arn"

	// OtterizeAWSUseSoftDeleteKey is used to mark workloads that should not have their corresponding roles deleted,
	// but should be tagged as deleted instead (aka soft delete strategy).
	OtterizeAWSUseSoftDeleteKey   = "credentials-operator.otterize.com/aws-use-soft-delete"
	OtterizeAWSUseSoftDeleteValue = "true"
)

type Agent struct {
	*awsagent.Agent
	markRolesAsUnusedInsteadOfDelete bool
	enableAWSRoleAnywhere            bool
	trustAnchorArn                   string
}

func NewAWSCredentialsAgent(awsAgent *awsagent.Agent, markRolesAsUnusedInsteadOfDelete bool, enableAWSRoleAnywhere bool, trustAnchorArn string) *Agent {
	return &Agent{awsAgent, markRolesAsUnusedInsteadOfDelete, enableAWSRoleAnywhere, trustAnchorArn}
}

func (a *Agent) OnPodAdmission(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount) (updated bool, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	if !a.AppliesOnPod(pod) {
		logger.Debug("Pod is not marked for AWS IAM role, skipping")
		return false, nil
	}

	serviceAccount.Labels[ServiceManagedByAWSAgentLabel] = "true"

	roleArn := a.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
	serviceAccount.Annotations[ServiceAccountAWSRoleARNAnnotation] = roleArn
	pod.Annotations[OtterizeServiceAccountAWSRoleARNAnnotation] = roleArn

	podUseSoftDeleteLabelValue, podUseSoftDeleteLabelExists := pod.Labels[OtterizeAWSUseSoftDeleteKey]
	shouldMarkForSoftDelete := podUseSoftDeleteLabelExists && podUseSoftDeleteLabelValue == OtterizeAWSUseSoftDeleteValue
	logger.Debugf("should mark for soft delete: %v, labels: %v", shouldMarkForSoftDelete, pod.Labels)
	if shouldMarkForSoftDelete {
		logger.Debugf("Add soft-delete label to service account")
		serviceAccount.Labels[OtterizeAWSUseSoftDeleteKey] = OtterizeAWSUseSoftDeleteValue
	} else {
		delete(serviceAccount.Labels, OtterizeAWSUseSoftDeleteKey)
	}

	if a.enableAWSRoleAnywhere {
		// In RolesAnywhere mode, the pod webhook, and not the reconciler, handles the role creation
		dryRun := false // TODO

		if pod.Spec.Volumes == nil {
			pod.Spec.Volumes = make([]corev1.Volume, 0)
		}

		_, role, profile, err := a.reconcileAWSRole(ctx, serviceAccount, dryRun)
		if err != nil {
			return false, errors.Errorf("failed reconciling AWS role: %w", err)
		}

		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "spiffe",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{
					Driver:   "spiffe.csi.cert-manager.io",
					ReadOnly: lo.ToPtr(true),
					VolumeAttributes: map[string]string{
						"aws.spiffe.csi.cert-manager.io/trust-profile": *profile.ProfileArn,
						"aws.spiffe.csi.cert-manager.io/trust-anchor":  a.trustAnchorArn,
						"aws.spiffe.csi.cert-manager.io/role":          *role.Arn,
						"aws.spiffe.csi.cert-manager.io/enable":        "true",
					},
				},
			},
		})

		for i := range pod.Spec.Containers {
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, corev1.VolumeMount{
				Name:      "spiffe",
				MountPath: "/aws-config",
				ReadOnly:  true,
			})
			pod.Spec.Containers[i].Env = append(pod.Spec.Containers[i].Env, corev1.EnvVar{
				Name:  "AWS_SHARED_CREDENTIALS_FILE",
				Value: "/aws-config/credentials",
			})
		}

	}

	return true, nil
}
func (a *Agent) reconcileAWSRole(ctx context.Context, serviceAccount *corev1.ServiceAccount, dryRun bool) (updateAnnotation bool, role *awstypes.Role, profile *rolesanywhereTypes.ProfileDetail, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})
	if dryRun {
		return false, &awstypes.Role{
				Arn: lo.ToPtr("dry-run-role-arn"),
			}, &rolesanywhereTypes.ProfileDetail{
				ProfileArn: lo.ToPtr("dry-run-profile-arn"),
			}, nil
	}

	if roleARN, ok := hasAWSAnnotation(serviceAccount); ok {
		generatedRoleARN := a.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
		found, role, err := a.GetOtterizeRole(ctx, serviceAccount.Namespace, serviceAccount.Name)

		if err != nil {
			return false, nil, nil, errors.Errorf("failed getting AWS role: %w", err)
		}

		foundProfile, profile, err := a.GetOtterizeProfile(ctx, serviceAccount.Namespace, serviceAccount.Name)
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

	role, err = a.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name, false /* FIXME */)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	profile, err = a.CreateRolesAnywhereProfileForRole(ctx, *role, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating rolesanywhere profile for role: %w", err)
	}
	logger.WithField("arn", *profile.ProfileId).Info("created AWS profile for ServiceAccount")

	return true, role, profile, nil
}

func (a *Agent) OnServiceAccountUpdate(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	roleARN, ok := hasAWSAnnotation(serviceAccount)

	if serviceAccount.Labels == nil || serviceAccount.Labels[ServiceManagedByAWSAgentLabel] != "true" {
		logger.Debug("ServiceAccount is not managed by the AWS agent, skipping")
		return false, false, nil
	}

	if a.enableAWSRoleAnywhere {
		// In RolesAnywhere mode, the SPIFFE pod webhook, and not the reconciler, handles the role creation
		return false, false, nil
	}

	role, err := a.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name, a.shouldUseSoftDeleteStrategy(serviceAccount))

	if err != nil {
		return false, false, fmt.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	// update annotation if it doesn't exist or if it is misconfigured
	shouldUpdateAnnotation := !ok || roleARN != *role.Arn
	if !shouldUpdateAnnotation {
		return false, false, nil
	}

	serviceAccount.Annotations[ServiceAccountAWSRoleARNAnnotation] = *role.Arn
	return true, false, nil
}

func (a *Agent) shouldUseSoftDeleteStrategy(serviceAccount *corev1.ServiceAccount) bool {
	if a.markRolesAsUnusedInsteadOfDelete {
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
	if serviceAccount.Labels == nil || serviceAccount.Labels[ServiceManagedByAWSAgentLabel] != "true" {
		logger.Debug("ServiceAccount is not managed by the AWS agent, skipping")
		return nil
	}

	err := a.DeleteOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return fmt.Errorf("failed to remove service account: %w", err)
	}

	if a.enableAWSRoleAnywhere {
		deleted, err := a.DeleteRolesAnywhereProfileForServiceAccount(ctx, serviceAccount.Namespace, serviceAccount.Name)
		if err != nil {
			return fmt.Errorf("failed to remove rolesanywhere profile for service account: %w", err)
		}

		if !deleted {
			logger.Debug("rolesanywhere profile for service account did not exist when deletion was attempted")
		}

		logger.Debug("deleted rolesanywhere profile for service account")
	}

	return nil
}
