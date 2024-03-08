package spiffe_rolesanywhere_pod_webhook

import (
	"context"
	"encoding/json"
	"fmt"
	awstypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	rolesanywhereTypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/otterize/intents-operator/src/shared/awsagent"
	"github.com/otterize/intents-operator/src/shared/errors"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"time"
)

// +kubebuilder:webhook:path=/mutate-v1-pod,mutating=true,failurePolicy=ignore,groups="",sideEffects=NoneOnDryRun,resources=pods,verbs=create;update,versions=v1,admissionReviewVersions=v1,name=pods.credentials-operator.otterize.com
// +kubebuilder:rbac:groups="admissionregistration.k8s.io",resources=mutatingwebhookconfigurations,verbs=get;update;patch;list

type SPIFFEAWSRolePodWebhook struct {
	client         client.Client
	decoder        *admission.Decoder
	awsAgent       *awsagent.Agent
	trustAnchorArn string
}

func NewSPIFFEAWSRolePodWebhook(mgr manager.Manager, awsAgent *awsagent.Agent, trustAnchorArn string) *SPIFFEAWSRolePodWebhook {
	return &SPIFFEAWSRolePodWebhook{
		client:         mgr.GetClient(),
		decoder:        admission.NewDecoder(mgr.GetScheme()),
		awsAgent:       awsAgent,
		trustAnchorArn: trustAnchorArn,
	}
}

func (a *SPIFFEAWSRolePodWebhook) handleOnce(ctx context.Context, pod corev1.Pod, dryRun bool) (outputPod corev1.Pod, patched bool, successMsg string, err error) {
	if pod.DeletionTimestamp != nil {
		return pod, false, "no webhook handling if pod is terminating", nil
	}

	if pod.Labels == nil {
		return pod, false, "no create AWS role label - no modifications made", nil
	}

	if controllerutil.ContainsFinalizer(&pod, metadata.AWSRoleFinalizer) {
		return pod, false, "pod already handled by webhook", nil
	}

	_, labelExists := pod.Labels[metadata.CreateAWSRoleLabel]
	if !labelExists {
		logrus.Debugf("pod %v doesn't have create AWS IAM role label, skipping", pod.Name)
		return pod, false, "no create AWS role label - no modifications made", nil
	}

	var serviceAccount corev1.ServiceAccount
	err = a.client.Get(ctx, types.NamespacedName{
		Namespace: pod.Namespace,
		Name:      pod.Spec.ServiceAccountName,
	}, &serviceAccount)
	if err != nil {
		return corev1.Pod{}, false, "", errors.Errorf("could not get service account: %w", err)
	}

	roleArn := a.awsAgent.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)

	// add annotation to trigger reinvocation for AWS pod reconciler
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[metadata.OtterizeServiceAccountAWSRoleARNAnnotation] = roleArn
	if pod.Spec.Volumes == nil {
		pod.Spec.Volumes = make([]corev1.Volume, 0)
	}

	_, role, profile, err := a.reconcileAWSRole(ctx, serviceAccount, dryRun)
	if err != nil {
		return corev1.Pod{}, false, "", errors.Wrap(err)
	}

	updatedServiceAccount := serviceAccount.DeepCopy()

	if updatedServiceAccount.Annotations == nil {
		updatedServiceAccount.Annotations = make(map[string]string)
	}

	if updatedServiceAccount.Labels == nil {
		updatedServiceAccount.Labels = make(map[string]string)
	}

	updatedServiceAccount.Labels[metadata.OtterizeServiceAccountLabel] = metadata.OtterizeServiceAccountHasPodsValue

	podUseSoftDeleteLabelValue, podUseSoftDeleteLabelExists := pod.Labels[metadata.OtterizeAWSUseSoftDeleteKey]
	shouldMarkForSoftDelete := podUseSoftDeleteLabelExists && podUseSoftDeleteLabelValue == metadata.OtterizeAWSUseSoftDeleteValue
	logrus.Debugf("pod %s, namespace %s, should mark for soft delete: %v, labels: %v", pod.Name, pod.Namespace, shouldMarkForSoftDelete, pod.Labels)
	if shouldMarkForSoftDelete {
		logrus.Debugf("Add soft-delete label to service account %s, namespace %s", updatedServiceAccount.Name, updatedServiceAccount.Namespace)
		updatedServiceAccount.Labels[metadata.OtterizeAWSUseSoftDeleteKey] = metadata.OtterizeAWSUseSoftDeleteValue
	} else {
		delete(updatedServiceAccount.Labels, metadata.OtterizeAWSUseSoftDeleteKey)
	}

	controllerutil.AddFinalizer(updatedServiceAccount, metadata.AWSRoleFinalizer)

	if !dryRun {
		err = a.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
		if err != nil {
			return corev1.Pod{}, false, "", fmt.Errorf("could not update service account: %w", err)
		}
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

	controllerutil.AddFinalizer(&pod, metadata.AWSRoleFinalizer)
	return pod, true, "pod and service account updated to create AWS role", nil
}

func (a *SPIFFEAWSRolePodWebhook) reconcileAWSRole(ctx context.Context, serviceAccount corev1.ServiceAccount, dryRun bool) (updateAnnotation bool, role *awstypes.Role, profile *rolesanywhereTypes.ProfileDetail, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})
	if dryRun {
		return false, &awstypes.Role{
				Arn: lo.ToPtr("dry-run-role-arn"),
			}, &rolesanywhereTypes.ProfileDetail{
				ProfileArn: lo.ToPtr("dry-run-profile-arn"),
			}, nil
	}

	if roleARN, ok := hasAWSAnnotation(serviceAccount); ok {
		generatedRoleARN := a.awsAgent.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
		found, role, err := a.awsAgent.GetOtterizeRole(ctx, serviceAccount.Namespace, serviceAccount.Name)

		if err != nil {
			return false, nil, nil, errors.Errorf("failed getting AWS role: %w", err)
		}

		foundProfile, profile, err := a.awsAgent.GetOtterizeProfile(ctx, serviceAccount.Namespace, serviceAccount.Name)
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

	role, err = a.awsAgent.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name, false /* FIXME */)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	profile, err = a.awsAgent.CreateRolesAnywhereProfileForRole(ctx, *role, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating rolesanywhere profile for role: %w", err)
	}
	logger.WithField("arn", *profile.ProfileId).Info("created AWS profile for ServiceAccount")

	return true, role, profile, nil
}

func hasAWSAnnotation(serviceAccount corev1.ServiceAccount) (string, bool) {
	if serviceAccount.Annotations == nil {
		return "", false
	}

	roleARN, ok := serviceAccount.Annotations[metadata.ServiceAccountAWSRoleARNAnnotation]
	return roleARN, ok
}

// dryRun: should not cause any modifications except to the Pod in the request.
func (a *SPIFFEAWSRolePodWebhook) handleWithRetriesOnConflictOrNotFound(ctx context.Context, pod corev1.Pod, dryRun bool) (outputPod corev1.Pod, patched bool, successMsg string, err error) {
	for attempt := 0; attempt < 5; attempt++ {
		logrus.Debugf("Handling pod '%s' in namespace '%s' (attempt %d out of %d)", pod.Name, pod.Namespace, attempt+1, 3)
		outputPod, patched, successMsg, err = a.handleOnce(ctx, *pod.DeepCopy(), dryRun)
		if err != nil {
			if k8serrors.IsConflict(err) || k8serrors.IsNotFound(err) {
				logrus.WithError(err).Errorf("failed to handle pod '%s' in namespace '%s' due to conflict, retrying in 1 second (attempt %d out of %d)", pod.Name, pod.Namespace, attempt+1, 3)
				time.Sleep(1 * time.Second)
				continue
			}
			return corev1.Pod{}, false, "", errors.Wrap(err)
		}
		return outputPod, patched, successMsg, nil
	}
	if err != nil {
		return corev1.Pod{}, false, "", errors.Wrap(err)
	}
	panic("unreachable - must have received error or it would have exited in the for loop")
}

func (a *SPIFFEAWSRolePodWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := corev1.Pod{}
	err := a.decoder.Decode(req, &pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	logrus.Debugf("Got webhook call for pod '%s' in namespace '%s'", pod.Name, pod.Namespace)

	pod, patched, successMsg, err := a.handleWithRetriesOnConflictOrNotFound(ctx, pod, req.DryRun != nil && *req.DryRun)
	if err != nil {
		logrus.WithError(err).Errorf("failed to annotate service account, but pod admitted to ensure success")
		return admission.Allowed("pod admitted, but failed to annotate service account, see warnings").WithWarnings(err.Error())
	}

	if !patched {
		return admission.Allowed(successMsg)
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}
