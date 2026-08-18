// Package target extracts a common representation out of the two Kinds the
// operator watches (Ingress and HTTPRoute), so the reconcile logic doesn't
// need to know which one it's looking at.
package target

import (
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Kind identifies which watched type a Target came from.
type Kind string

const (
	KindIngress   Kind = "Ingress"
	KindHTTPRoute Kind = "HTTPRoute"
)

// Backend is a single, unambiguous backend Service+port a Target routes to.
type Backend struct {
	ServiceName string
	Port        int32
}

// Target is the common shape of an annotated Ingress or HTTPRoute.
type Target struct {
	Kind        Kind
	Namespace   string
	Name        string
	UID         types.UID
	Annotations map[string]string
	Hostnames   []string

	// Backend is non-nil only when the resource has exactly one
	// unambiguous backend Service+port; proxy mode falls back to it when
	// authentik.gddnet.io/proxy-internal-host isn't set.
	Backend *Backend
}

// InternalHostURL renders Backend as the in-cluster URL authentik's proxy
// provider should forward to.
func (t *Target) InternalHostURL() string {
	if t.Backend == nil {
		return ""
	}
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", t.Backend.ServiceName, t.Namespace, t.Backend.Port)
}

// FromIngress builds a Target from a networking.k8s.io/v1 Ingress.
func FromIngress(ing *networkingv1.Ingress) *Target {
	t := &Target{
		Kind:        KindIngress,
		Namespace:   ing.Namespace,
		Name:        ing.Name,
		UID:         ing.UID,
		Annotations: ing.Annotations,
	}

	for _, rule := range ing.Spec.Rules {
		if rule.Host != "" {
			t.Hostnames = append(t.Hostnames, rule.Host)
		}
	}

	t.Backend = singleIngressBackend(ing)
	return t
}

func singleIngressBackend(ing *networkingv1.Ingress) *Backend {
	var backends []*networkingv1.IngressServiceBackend
	if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
		backends = append(backends, ing.Spec.DefaultBackend.Service)
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			if p.Backend.Service != nil {
				backends = append(backends, p.Backend.Service)
			}
		}
	}

	if len(backends) != 1 {
		return nil
	}
	svc := backends[0]
	if svc.Port.Number == 0 {
		return nil
	}
	return &Backend{ServiceName: svc.Name, Port: svc.Port.Number}
}

// FromHTTPRoute builds a Target from a gateway.networking.k8s.io/v1 HTTPRoute.
func FromHTTPRoute(r *gatewayv1.HTTPRoute) *Target {
	t := &Target{
		Kind:        KindHTTPRoute,
		Namespace:   r.Namespace,
		Name:        r.Name,
		UID:         r.UID,
		Annotations: r.Annotations,
	}

	for _, h := range r.Spec.Hostnames {
		t.Hostnames = append(t.Hostnames, string(h))
	}

	t.Backend = singleHTTPRouteBackend(r)
	return t
}

func singleHTTPRouteBackend(r *gatewayv1.HTTPRoute) *Backend {
	var refs []gatewayv1.HTTPBackendRef
	for _, rule := range r.Spec.Rules {
		refs = append(refs, rule.BackendRefs...)
	}
	if len(refs) != 1 || refs[0].Port == nil || refs[0].Name == "" {
		return nil
	}
	return &Backend{ServiceName: string(refs[0].Name), Port: int32(*refs[0].Port)}
}
