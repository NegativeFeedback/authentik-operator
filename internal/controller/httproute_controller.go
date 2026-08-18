package controller

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/negativefeedback/authentik-operator/internal/target"
)

// HTTPRouteReconciler watches gateway.networking.k8s.io/v1 HTTPRoute objects
// for authentik.gddnet.io/* annotations. It also owns the proxy-mode routes
// it creates itself (same Kind, so one watch/reconcile loop covers both).
type HTTPRouteReconciler struct {
	Shared *Shared
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var route gatewayv1.HTTPRoute
	if err := r.Shared.Client.Get(ctx, req.NamespacedName, &route); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Routes the operator itself creates for proxy mode never carry
	// authentik.gddnet.io/enabled, so target.FromHTTPRoute on them yields a
	// no-op Reconcile — nothing to special-case here.
	t := target.FromHTTPRoute(&route)
	if err := r.Shared.Reconcile(ctx, &route, t); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Named("httproute").
		Complete(r)
}
