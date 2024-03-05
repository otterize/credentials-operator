package iam

import (
	"context"
	corev1 "k8s.io/api/core/v1"
)

type IAMCredentialsAgent interface {
	ApplyOnPodLabel() string
	ServiceManagedByLabel() string
	OnPodAdmission(pod *corev1.Pod, serviceAccount *corev1.ServiceAccount) (updated bool)
	ReconcileServiceIAMRole(ctx context.Context, serviceAccount *corev1.ServiceAccount, useSoftDeleteStrategy bool) (updated bool, requeue bool, err error)
	DeleteServiceIAMRole(ctx context.Context, namespace string, name string) error
}
