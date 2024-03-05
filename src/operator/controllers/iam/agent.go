package iam

import (
	"context"
	corev1 "k8s.io/api/core/v1"
)

type IAMCredentialsAgent interface {
	OnPodAdmission(pod *corev1.Pod, serviceAccount *corev1.ServiceAccount) (updated bool)
	OnServiceAccountUpdate(ctx context.Context, serviceAccount *corev1.ServiceAccount) (updated bool, requeue bool, err error)
	OnServiceAccountTermination(ctx context.Context, serviceAccount *corev1.ServiceAccount) error
}
