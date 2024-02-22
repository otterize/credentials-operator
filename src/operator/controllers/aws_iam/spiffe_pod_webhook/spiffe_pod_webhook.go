package sa_pod_webhook

import (
	"context"
	"encoding/json"
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

	updatedServiceAccount := serviceAccount.DeepCopy()

	if updatedServiceAccount.Annotations == nil {
		updatedServiceAccount.Annotations = make(map[string]string)
	}

	if updatedServiceAccount.Labels == nil {
		updatedServiceAccount.Labels = make(map[string]string)
	}

	// we don't actually create the role here, so that the webhook returns quickly - a ServiceAccount reconciler takes care of it for us.
	//updatedServiceAccount.Annotations[metadata.ServiceAccountAWSRoleARNAnnotation] = roleArn
	//updatedServiceAccount.Labels[metadata.OtterizeServiceAccountLabel] = metadata.OtterizeServiceAccountHasPodsValue
	//if !dryRun {
	//	err = a.client.Patch(ctx, updatedServiceAccount, client.MergeFrom(&serviceAccount))
	//	if err != nil {
	//		return corev1.Pod{}, false, "", errors.Errorf("could not update service account: %w", err)
	//	}
	//}

	// add annotation to trigger reinvocation for AWS pod reconciler
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations[metadata.OtterizeServiceAccountAWSRoleARNAnnotation] = roleArn
	if pod.Spec.Volumes == nil {
		pod.Spec.Volumes = make([]corev1.Volume, 0)
	}

	_, role, profile, err := a.reconcileAWSRole(ctx, updatedServiceAccount)
	if err != nil {
		return corev1.Pod{}, false, "", errors.Wrap(err)
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

	//         - name: spiffe
	//          csi:
	//            driver: spiffe.csi.cert-manager.io
	//            readOnly: true
	//            volumeAttributes:
	//              aws.spiffe.csi.cert-manager.io/trust-profile: "arn:aws:rolesanywhere:eu-west-2:228615251467:profile/a37adb60-1972-4450-ae56-fba0947503f1"
	//              aws.spiffe.csi.cert-manager.io/trust-anchor: "arn:aws:rolesanywhere:eu-west-2:228615251467:trust-anchor/783a334a-9244-4279-9fb3-cea38c65ce3f"
	//              aws.spiffe.csi.cert-manager.io/role: "arn:aws:iam::228615251467:role/otterize-role"
	//              aws.spiffe.csi.cert-manager.io/enable: "true"

	controllerutil.AddFinalizer(&pod, metadata.AWSRoleFinalizer)
	return pod, true, "pod and service account updated to create AWS role", nil
}

func (a *SPIFFEAWSRolePodWebhook) reconcileAWSRole(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updateAnnotation bool, role *awstypes.Role, profile *rolesanywhereTypes.ProfileDetail, err error) {
	logger := logrus.WithFields(logrus.Fields{"serviceAccount": serviceAccount.Name, "namespace": serviceAccount.Namespace})

	if roleARN, ok := hasAWSAnnotation(serviceAccount); ok {
		generatedRoleARN := a.awsAgent.GenerateRoleARN(serviceAccount.Namespace, serviceAccount.Name)
		found, role, err := a.awsAgent.GetOtterizeRole(ctx, serviceAccount.Namespace, serviceAccount.Name)

		if err != nil {
			return false, nil, nil, errors.Errorf("failed getting AWS role: %w", err)
		}

		if found {
			if generatedRoleARN != roleARN {
				logger.WithField("arn", *role.Arn).Debug("ServiceAccount AWS role exists, but annotation is misconfigured, should be updated")
				return true, role, nil, nil
			}
			logger.WithField("arn", *role.Arn).Debug("ServiceAccount has matching AWS role")
			//return false, role, nil, nil
		}
	}

	role, err = a.awsAgent.CreateOtterizeIAMRole(ctx, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating AWS role for service account: %w", err)
	}
	logger.WithField("arn", *role.Arn).Info("created AWS role for ServiceAccount")

	profile, err = a.awsAgent.CreateRolesAnywhereProfileForRole(ctx, *role, serviceAccount.Namespace, serviceAccount.Name)
	if err != nil {
		return false, nil, nil, errors.Errorf("failed creating rolesanywhere profile for role: %w", err)
	}
	logger.WithField("arn", *profile.ProfileId).Info("created AWS role for ServiceAccount")

	return true, role, profile, nil
}

func hasAWSAnnotation(serviceAccount *corev1.ServiceAccount) (string, bool) {
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
