package controller

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/negativefeedback/authentik-operator/internal/target"
)

// IngressReconciler watches networking.k8s.io/v1 Ingress objects for
// authentik.gddnet.io/* annotations.
type IngressReconciler struct {
	Shared *Shared
}

func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ing networkingv1.Ingress
	if err := r.Shared.Client.Get(ctx, req.NamespacedName, &ing); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	t := target.FromIngress(&ing)
	if err := r.Shared.Reconcile(ctx, &ing, t); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkingv1.Ingress{}).
		Named("ingress").
		Complete(r)
}
