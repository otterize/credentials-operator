package certmanageradapter

import (
	"context"
	"fmt"
	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/otterize/credentials-operator/src/controllers/metadata"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// CertificateApprover - This class is inspired by and shares code with https://github.com/cert-manager/csi-driver-spiffe/tree/main/internal/approver/ *
type CertificateApprover struct {
	mgr       manager.Manager
	issuerRef cmmeta.ObjectReference
	registry  *CertManagerWorkloadRegistry
}

func NewCertificateApprover(issuerRef cmmeta.ObjectReference, mgr manager.Manager, registry *CertManagerWorkloadRegistry) *CertificateApprover {
	return &CertificateApprover{
		issuerRef: issuerRef,
		mgr:       mgr,
		registry:  registry,
	}
}

func (a *CertificateApprover) Register(ctx context.Context) error {
	log := logrus.WithFields(logrus.Fields{"name": "cert-request-aprrover"})

	return ctrl.NewControllerManagedBy(a.mgr).
		For(new(cmapi.CertificateRequest)).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			var req cmapi.CertificateRequest
			err := a.mgr.GetCache().Get(ctx, client.ObjectKeyFromObject(obj), &req)
			if apierrors.IsNotFound(err) {
				// Ignore CertificateRequests that have been deleted.
				return false
			}

			// If an error happens here and we do nothing, we run the risk of not
			// processing CertificateRequests.
			// Exiting error is the safest option, as it will force a resync on all
			// CertificateRequests on start.
			if err != nil {
				log.Error(err, "failed to list all CertificateRequests, exiting error")
				os.Exit(-1)
			}

			// Ignore requests that already have an Approved or Denied condition.
			if apiutil.CertificateRequestIsApproved(&req) || apiutil.CertificateRequestIsDenied(&req) {
				return false
			}

			return req.Spec.IssuerRef == a.issuerRef
		})).
		Complete(a)
}

// Reconcile is called when a CertificateRequest is synced which has been
// neither approved or denied yet, and matches the issuerRef configured.
func (a *CertificateApprover) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logrus.WithFields(logrus.Fields{"namespace": req.NamespacedName.Namespace, "name": req.NamespacedName.Name})
	log.Info("syncing certificaterequest")
	defer log.Info("finished syncing certificaterequest")

	var cr cmapi.CertificateRequest
	if err := a.mgr.GetCache().Get(ctx, req.NamespacedName, &cr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := a.Evaluate(&cr); err != nil {
		log.Error(err, "denying request")
		apiutil.SetCertificateRequestCondition(&cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue, "spiffe.csi.cert-manager.io", "Denied request: "+err.Error())
		return ctrl.Result{}, a.mgr.GetClient().Status().Update(ctx, &cr)
	}

	log.Info("approving request")
	apiutil.SetCertificateRequestCondition(&cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue, "spiffe.csi.cert-manager.io", "Approved request")
	return ctrl.Result{}, a.mgr.GetClient().Status().Update(ctx, &cr)
}

// Evaluate evaluates whether a CertificateRequest should be approved or
// denied. A CertificateRequest should be denied if this function returns an
// error, should be approved otherwise.
func (a *CertificateApprover) Evaluate(req *cmapi.CertificateRequest) error {
	csr, err := utilpki.DecodeX509CertificateRequestBytes(req.Spec.Request)
	if err != nil {
		return fmt.Errorf("failed to parse request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("signature check failed for csr: %w", err)
	}

	// if the csr contains any other options set, error
	if len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 {
		return fmt.Errorf("forbidden extensions, IPs=%q Emails=%q",
			csr.IPAddresses, csr.EmailAddresses)
	}

	if req.Spec.IsCA {
		return fmt.Errorf("request contains spec.isCA=true")
	}

	entryId, ok := req.Annotations[metadata.TLSSecretEntryIDAnnotation]
	if !ok {
		return fmt.Errorf("credentials-operator's annotation not found")
	}

	if a.registry.getPodEntryById(entryId) == nil {
		return fmt.Errorf("entry-id does not exist: %q", entryId)
	}

	return nil
}
