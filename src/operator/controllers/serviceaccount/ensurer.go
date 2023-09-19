package serviceaccount

import (
	"context"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Ensurer struct {
	client.Client
}

func NewServiceAccountEnsurer(client client.Client) *Ensurer {
	return &Ensurer{client}
}

func isServiceAccountNameValid(name string) bool {
	return len(validation.IsDNS1123Subdomain(name)) == 0
}

func (e *Ensurer) EnsureServiceAccount(ctx context.Context, pod *v1.Pod) error {
	if pod.Annotations == nil {
		return nil
	}
	serviceAccountName, annotationExists := pod.Annotations[metadata.ServiceAccountNameAnnotation]
	if !annotationExists {
		logrus.Debugf("skiping ensure service account for pod %s", pod)
		return nil
	}

	if !isServiceAccountNameValid(serviceAccountName) {
		logrus.Debugf("service account name %s is invalid according to 'RFC 1123 subdomain'. skipping service account ensure for pod %s", serviceAccountName, pod)
		return nil
	}

	serviceAccount := v1.ServiceAccount{}
	err := e.Client.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: serviceAccountName}, &serviceAccount)
	if apierrors.IsNotFound(err) {
		return e.createServiceAccount(ctx, serviceAccountName, pod)
	} else if err != nil {
		return err
	}
	return nil
}

func (e *Ensurer) createServiceAccount(ctx context.Context, serviceAccountName string, pod *v1.Pod) error {
	serviceAccount := v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: serviceAccountName, Namespace: pod.Namespace},
	}
	return e.Client.Create(ctx, &serviceAccount)
}
