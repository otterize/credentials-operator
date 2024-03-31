package iamcredentialsagents

import (
	"context"
	corev1 "k8s.io/api/core/v1"
)

type IAMCredentialsAgent interface {
	FinalizerName() string
	ServiceAccountLabel() string
	OnPodAdmission(ctx context.Context, pod *corev1.Pod, serviceAccount *corev1.ServiceAccount, dryRun bool) (updated bool, err error)
	OnServiceAccountUpdate(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error)
	OnServiceAccountTermination(ctx context.Context, serviceAccount *corev1.ServiceAccount) error
}
