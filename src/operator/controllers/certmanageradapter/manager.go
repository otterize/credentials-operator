package certmanageradapter

import (
	"context"
	"fmt"
	"github.com/amit7itz/goset"
	certmanager "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	secretstypes "github.com/otterize/credentials-operator/src/controllers/secrets/types"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"
)

const (
	secretExpiryDelta = 10 * time.Minute
	CertRenewReason   = "CertificateRenewed"
)

// TODO: Share with the other class
func SecretConfigFromAnnotations(annotations map[string]string) secretstypes.SecretConfig {
	_, shouldRestartOnRenewalBool := annotations[metadata.ShouldRestartOnRenewalAnnotation]
	return secretstypes.SecretConfig{
		ServiceName:               annotations[metadata.TLSSecretRegisteredServiceNameAnnotation],
		EntryID:                   annotations[metadata.TLSSecretEntryIDAnnotation],
		EntryHash:                 annotations[metadata.TLSSecretEntryHashAnnotation],
		ShouldRestartPodOnRenewal: shouldRestartOnRenewalBool,
		CertConfig: secretstypes.CertConfig{
			CertType:  secretstypes.CertType(annotations[metadata.CertTypeAnnotation]),
			PEMConfig: secretstypes.PEMConfig{
				//CertFileName: annotations[metadata.CertFileNameAnnotation],
				//CAFileName:   annotations[metadata.CAFileNameAnnotation],
				//KeyFileName:  annotations[metadata.KeyFileNameAnnotation],
			},
			JKSConfig: secretstypes.JKSConfig{
				//KeyStoreFileName:   annotations[metadata.KeyStoreFileNameAnnotation],
				//TrustStoreFileName: annotations[metadata.TrustStoreFileNameAnnotation],
				Password: annotations[metadata.JKSPasswordAnnotation],
			},
		},
	}
}

func SecretConfigFromExistingCertificate(certificate *certmanager.Certificate) secretstypes.SecretConfig {
	config := SecretConfigFromAnnotations(certificate.Annotations)
	config.SecretName = certificate.Spec.SecretName
	config.Namespace = certificate.Namespace
	return config
}

type CertificateEntry struct {
	EntryId          string
	Namespace        string
	ServiceNameLabel string
	ServiceName      string
	Ttl              int32
	DnsNames         []string
}

// TODO: Somehow share with KubernetesSecretsManager
type CertManagerAdapter struct {
	client.Client
	eventRecorder     record.EventRecorder
	serviceIdResolver secretstypes.ServiceIdResolver
	entries           map[string]*CertificateEntry
	issuerName        string
}

func NewCertManagerSecretsAdapter(
	c client.Client,
	serviceIdResolver secretstypes.ServiceIdResolver,
	eventRecorder record.EventRecorder,
	issuerName string) *CertManagerAdapter {
	return &CertManagerAdapter{Client: c,
		serviceIdResolver: serviceIdResolver,
		eventRecorder:     eventRecorder,
		entries:           make(map[string]*CertificateEntry),
		issuerName:        issuerName,
	}
}

func (m *CertManagerAdapter) getEntryId(namespace, serviceName string) string {
	return fmt.Sprintf("%s.%s", serviceName, namespace)
}

// TODO: The following 2 should be another class
func (m *CertManagerAdapter) RegisterK8SPod(ctx context.Context, namespace string, serviceNameLabel string, serviceName string, ttl int32, dnsNames []string) (string, error) {
	entryId := m.getEntryId(namespace, serviceName)
	// TODO: What if already exists?
	m.entries[entryId] = &CertificateEntry{
		EntryId:          entryId,
		Namespace:        namespace,
		ServiceNameLabel: serviceNameLabel,
		ServiceName:      serviceName,
		Ttl:              ttl,
		DnsNames:         dnsNames,
	}
	return entryId, nil
}

func (m *CertManagerAdapter) CleanupOrphanK8SPodEntries(ctx context.Context, serviceNameLabel string, existingServicesByNamespace map[string]*goset.Set[string]) error {
	for entryId, entry := range m.entries {
		nsServices, nsExists := existingServicesByNamespace[entry.Namespace]
		if nsExists {
			if nsServices.Contains(entry.ServiceName) {
				continue
			}
		}
		delete(m.entries, entryId)
	}
	return nil
}

func (m *CertManagerAdapter) getPodEntry(namespace, serviceName string) *CertificateEntry {
	// TODO: What if doesn't exist?
	return m.entries[m.getEntryId(namespace, serviceName)]
}

func (m *CertManagerAdapter) isRefreshNeeded(*certmanager.Certificate) bool {
	return false
}

func (m *CertManagerAdapter) getExistingCertificate(ctx context.Context, namespace string, name string) (*certmanager.Certificate, bool, error) {
	// todo: generics?
	found := certmanager.Certificate{}
	if err := m.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &found); err != nil && apierrors.IsNotFound(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	return &found, true, nil
}

func (m *CertManagerAdapter) getJKSPasswordSecretRef(ctx context.Context, namespace, secretName, password string) (*cmmeta.SecretKeySelector, error) {
	jksPasswordsSecret := corev1.Secret{}
	newJksPasswordsSecret := false

	// TODO: const for the name
	if err := m.Get(ctx, types.NamespacedName{Name: "jks-passwords", Namespace: namespace}, &jksPasswordsSecret); err != nil {
		if apierrors.IsNotFound(err) {
			jksPasswordsSecret.Name = "jks-passwords"
			jksPasswordsSecret.Namespace = namespace
			jksPasswordsSecret.Data = make(map[string][]byte)
			newJksPasswordsSecret = true
		} else {
			return nil, err
		}
	}
	jksPasswordsSecret.Data[secretName] = []byte(password)

	if newJksPasswordsSecret {
		if err := m.Create(ctx, &jksPasswordsSecret); err != nil {
			logrus.WithError(err).Error("Can't create secret of jks passwords")
			return nil, err
		}
	} else {
		if err := m.Update(ctx, &jksPasswordsSecret); err != nil {
			logrus.WithError(err).Error("Can't update secret of jks passwords")
			return nil, err
		}
	}

	return &cmmeta.SecretKeySelector{
		LocalObjectReference: cmmeta.LocalObjectReference{
			Name: "jks-passwords",
		},
		Key: secretName,
	}, nil
}

func (m *CertManagerAdapter) updateTLSCertificate(ctx context.Context, config secretstypes.SecretConfig, certificate *certmanager.Certificate) error {
	// TODO: Can share with the other class
	certificate.Labels = map[string]string{
		metadata.SecretTypeLabel: string(secretstypes.TlsSecretType),
	}

	certificate.Annotations = map[string]string{
		// Not setting TLSSecretExpiryAnnotation because cert-manager is responsible for refreshing secrets
		metadata.TLSSecretRegisteredServiceNameAnnotation: config.ServiceName,
		metadata.TLSSecretEntryIDAnnotation:               config.EntryID,
		metadata.TLSSecretEntryHashAnnotation:             config.EntryHash,
		metadata.CertFileNameAnnotation:                   config.CertConfig.PEMConfig.CertFileName,
		metadata.CAFileNameAnnotation:                     config.CertConfig.PEMConfig.CAFileName,
		metadata.KeyFileNameAnnotation:                    config.CertConfig.PEMConfig.KeyFileName,
		metadata.KeyStoreFileNameAnnotation:               config.CertConfig.JKSConfig.KeyStoreFileName,
		metadata.TrustStoreFileNameAnnotation:             config.CertConfig.JKSConfig.TrustStoreFileName,
		metadata.JKSPasswordAnnotation:                    config.CertConfig.JKSConfig.Password,
		metadata.CertTypeAnnotation:                       string(config.CertConfig.CertType),
	}
	if config.ShouldRestartPodOnRenewal {
		// it only has to exist, we don't check the value
		certificate.Spec.SecretTemplate.Annotations[metadata.ShouldRestartOnRenewalAnnotation] = ""
	}

	// TODO: put in a different place
	entry := m.getPodEntry(config.Namespace, config.ServiceName)
	if entry.Ttl != 0 {
		certificate.Spec.Duration = &metav1.Duration{Duration: time.Duration(entry.Ttl) * time.Second}
	}
	certificate.Spec.DNSNames = entry.DnsNames
	certificate.Spec.CommonName = entry.EntryId
	certificate.Spec.IssuerRef.Kind = "Issuer" // TODO: Support ClusterIssuer as well
	certificate.Spec.IssuerRef.Name = m.issuerName

	if config.CertConfig.CertType == secretstypes.JKSCertType {
		jksPasswordRef, err := m.getJKSPasswordSecretRef(ctx, config.Namespace, config.SecretName, config.CertConfig.JKSConfig.Password)
		if err != nil {
			return err
		}

		certificate.Spec.Keystores = &certmanager.CertificateKeystores{
			JKS: &certmanager.JKSKeystore{
				Create:            true,
				PasswordSecretRef: *jksPasswordRef,
			},
		}
	}

	return nil
}

func (m *CertManagerAdapter) EnsureTLSSecret(ctx context.Context, config secretstypes.SecretConfig, pod *corev1.Pod) error {
	log := logrus.WithFields(logrus.Fields{"secret.namespace": config.Namespace, "secret.name": config.SecretName})

	existingCertificate, isExistingSecret, err := m.getExistingCertificate(ctx, config.Namespace, config.SecretName)
	if err != nil {
		log.WithError(err).Error("failed querying for certificate")
		return err
	}

	var certificate *certmanager.Certificate
	shouldUpdate := false

	if isExistingSecret {
		certificate = existingCertificate
	} else {
		certificate = &certmanager.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      config.SecretName,
				Namespace: config.Namespace,
			},
			Spec: certmanager.CertificateSpec{
				SecretName:     config.SecretName,
				SecretTemplate: &certmanager.CertificateSecretTemplate{},
				// TODO: Complete all that is needed
			},
		}
	}

	if !isExistingSecret ||
		m.isRefreshNeeded(certificate) ||
		m.isUpdateNeeded(SecretConfigFromExistingCertificate(certificate), config) {
		if err := m.updateTLSCertificate(ctx, config, certificate); err != nil {
			log.WithError(err).Error("failed updating TLS secret config")
			return err
		}
		shouldUpdate = true
	}

	ownerCount := len(certificate.OwnerReferences)
	if pod != nil {
		podOwner, err := m.serviceIdResolver.GetOwnerObject(ctx, pod)
		if err != nil {
			return err
		}
		if err := controllerutil.SetOwnerReference(podOwner, certificate, m.Scheme()); err != nil {
			log.WithError(err).Error("failed setting pod as owner reference")
			return err
		}
		shouldUpdate = shouldUpdate || len(certificate.OwnerReferences) != ownerCount
	}

	if isExistingSecret {
		if shouldUpdate {
			log.Info("Updating existing secret")
			if err := m.Update(ctx, certificate); err != nil {
				logrus.WithError(err).Error("failed updating existing secret")
				return err
			}
		}
	} else {
		log.Info("Creating a new secret")
		if err := m.Create(ctx, certificate); err != nil {
			logrus.WithError(err).Error("failed creating new secret")
			return err
		}
	}

	return nil
}

func (m *CertManagerAdapter) refreshTLSSecret(ctx context.Context, secret *corev1.Secret) error {
	//log := logrus.WithFields(logrus.Fields{"secret.namespace": secret.Namespace, "secret.name": secret.Name})
	//_, ok := secret.Annotations[metadata.TLSSecretRegisteredServiceNameAnnotation]
	//if !ok {
	//	return errors.New("service name annotation is missing")
	//}
	//
	//_, ok = secret.Annotations[metadata.TLSSecretEntryIDAnnotation]
	//
	//if !ok {
	//	return errors.New("entry ID annotation is missing")
	//}
	//
	//if err := m.updateTLSSecret(ctx, SecretConfigFromExistingSecret(secret), secret); err != nil {
	//	return err
	//}
	//
	//log.Info("Updating existing secret")
	//return m.Update(ctx, secret)
	return nil
}

func (m *CertManagerAdapter) RefreshTLSSecrets(ctx context.Context) error {
	//logrus.Info("refreshing TLS secrets")
	//secrets := corev1.SecretList{}
	//if err := m.List(ctx, &secrets, &client.MatchingLabels{metadata.SecretTypeLabel: string(secretstypes.TlsSecretType)}); err != nil {
	//	logrus.WithError(err).Error("failed listing TLS secrets")
	//	return err
	//}
	//
	//secretsNeedingRefresh := lo.Filter(
	//	secrets.Items,
	//	func(secret corev1.Secret, _ int) bool { return m.isRefreshNeeded(&secret) },
	//)
	//
	//log := logrus.WithFields(logrus.Fields{"secrets_count": len(secrets.Items), "refresh_count": len(secretsNeedingRefresh)})
	//log.Info("finished listing secrets")
	//
	//for _, secret := range secretsNeedingRefresh {
	//	log := logrus.WithFields(logrus.Fields{"secret.namespace": secret.Namespace, "secret.name": secret.Name})
	//	if err := m.refreshTLSSecret(ctx, &secret); err != nil {
	//		log.WithError(err).Error("failed refreshing TLS secret")
	//	}
	//	if err := m.handlePodRestarts(ctx, &secret); err != nil {
	//		log.WithError(err).Error("failed restarting pods after secret refresh")
	//	}
	//}
	//
	//log.Info("finished refreshing secrets")
	return nil
}

func (m *CertManagerAdapter) isUpdateNeeded(existingSecretConfig secretstypes.SecretConfig, newSecretConfig secretstypes.SecretConfig) bool {
	log := logrus.WithFields(logrus.Fields{"secret.namespace": existingSecretConfig.Namespace, "secret.name": existingSecretConfig.SecretName})
	needsUpdate := existingSecretConfig != newSecretConfig
	log.Infof("needs update: %v", needsUpdate)

	return needsUpdate
}

func (m *CertManagerAdapter) handlePodRestarts(ctx context.Context, secret *corev1.Secret) error {
	podList := corev1.PodList{}
	labelSelector, err := labels.Parse(fmt.Sprintf("%s=%s", metadata.RegisteredServiceNameLabel, secret.Annotations[metadata.RegisteredServiceNameLabel]))
	if err != nil {
		return err
	}

	err = m.List(ctx, &podList, &client.ListOptions{
		LabelSelector: labelSelector,
		Namespace:     secret.Namespace,
	})
	if err != nil {
		return err
	}
	// create unique owner list
	owners := make(map[secretstypes.PodOwnerIdentifier]client.Object)
	for _, pod := range podList.Items {
		if ok := metadata.AnnotationExists(pod.Annotations, metadata.ShouldRestartOnRenewalAnnotation); ok {
			owner, err := m.serviceIdResolver.GetOwnerObject(ctx, &pod)
			if err != nil {
				return err
			}
			owners[secretstypes.PodOwnerIdentifier{Name: owner.GetName(), GroupVersionKind: owner.GetObjectKind().GroupVersionKind()}] = owner
		}
	}
	for _, owner := range owners {
		logrus.Infof("Restarting pods for owner %s of type %s after certificate renewal",
			owner.GetName(), owner.GetObjectKind().GroupVersionKind().Kind)
		err = m.TriggerPodRestarts(ctx, owner, secret)
		if err != nil {
			return err
		}
	}

	return nil
}

// TriggerPodRestarts edits the pod owner's template spec with an annotation about the secret's expiry date
// If the secret is refreshed, its expiry will be updated in the pod owner's spec which will trigger the pods to restart
func (m *CertManagerAdapter) TriggerPodRestarts(ctx context.Context, owner client.Object, secret *corev1.Secret) error {
	kind := owner.GetObjectKind().GroupVersionKind().Kind
	switch kind {
	case "Deployment":
		deployment := v1.Deployment{}
		if err := m.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: owner.GetName()}, &deployment); err != nil {
			return err
		}
		deployment.Spec.Template = m.updatePodTemplateSpec(deployment.Spec.Template)
		if err := m.Update(ctx, &deployment); err != nil {
			return err
		}
		m.eventRecorder.Eventf(&deployment, corev1.EventTypeNormal, CertRenewReason, "Successfully restarted Deployment after secret '%s' renewal", secret.Name)
	case "ReplicaSet":
		replicaSet := v1.ReplicaSet{}
		if err := m.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: owner.GetName()}, &replicaSet); err != nil {
			return err
		}
		replicaSet.Spec.Template = m.updatePodTemplateSpec(replicaSet.Spec.Template)
		if err := m.Update(ctx, &replicaSet); err != nil {
			return err
		}
		m.eventRecorder.Eventf(&replicaSet, corev1.EventTypeNormal, CertRenewReason, "Successfully restarted ReplicaSet after secret '%s' renewal", secret.Name)
	case "StatefulSet":
		statefulSet := v1.StatefulSet{}
		if err := m.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: owner.GetName()}, &statefulSet); err != nil {
			return err
		}
		statefulSet.Spec.Template = m.updatePodTemplateSpec(statefulSet.Spec.Template)
		if err := m.Update(ctx, &statefulSet); err != nil {
			return err
		}
		m.eventRecorder.Eventf(&statefulSet, corev1.EventTypeNormal, CertRenewReason, "Successfully restarted StatefulSet after secret '%s' renewal", secret.Name)

	case "DaemonSet":
		daemonSet := v1.DaemonSet{}
		if err := m.Get(ctx, types.NamespacedName{Namespace: secret.Namespace, Name: owner.GetName()}, &daemonSet); err != nil {
			return err
		}
		daemonSet.Spec.Template = m.updatePodTemplateSpec(daemonSet.Spec.Template)
		if err := m.Update(ctx, &daemonSet); err != nil {
			return err
		}
		m.eventRecorder.Eventf(&daemonSet, corev1.EventTypeNormal, CertRenewReason, "Successfully restarted DaemonSet after secret '%s' renewal", secret.Name)

	default:
		return fmt.Errorf("unsupported owner type: %s", kind)
	}
	return nil
}

func (m *CertManagerAdapter) updatePodTemplateSpec(podTemplateSpec corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	if podTemplateSpec.Annotations == nil {
		podTemplateSpec.Annotations = map[string]string{}
	}
	podTemplateSpec.Annotations[metadata.TLSRestartTimeAfterRenewal] = time.Now().String()
	return podTemplateSpec
}
