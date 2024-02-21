package testutils

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testPodName            = "pod"
	testNamespace          = "namespace"
	testServiceAccountName = "serviceaccount"
	testPodUID             = "pod-uid"
)

func GetTestPodSchema() corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              testPodName,
			Namespace:         testNamespace,
			UID:               testPodUID,
			DeletionTimestamp: nil,
		},
		Spec: corev1.PodSpec{ServiceAccountName: testServiceAccountName},
	}
}
