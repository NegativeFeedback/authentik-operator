// Package controller implements the annotation-driven reconciliation shared
// by the Ingress and HTTPRoute controllers.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/negativefeedback/authentik-operator/internal/annotations"
	"github.com/negativefeedback/authentik-operator/internal/authentik"
	"github.com/negativefeedback/authentik-operator/internal/target"
)

// GatewayRef identifies the shared Gateway public HTTPRoutes in this cluster
// attach to (every route.yaml in kubernetes/apps uses external/kube-system/https).
type GatewayRef struct {
	Name        string
	Namespace   string
	SectionName string
}

// Shared implements the annotation -> Authentik + Secret + HTTPRoute
// reconciliation used by both the Ingress and HTTPRoute controllers.
type Shared struct {
	Client    client.Client
	Authentik *authentik.Client
	Gateway   GatewayRef

	// AuthentikNamespace/ServiceName/ServicePort locate the authentik-server
	// Service that fronts the embedded outpost. Proxy-mode HTTPRoutes are
	// created here (not in the target's own namespace) so the backendRef
	// never needs to cross namespaces, mirroring the existing hand-written
	// proxy-rook/proxy-paperless routes in
	// kubernetes/apps/gdd-security/authentik/app/route.yaml.
	AuthentikNamespace   string
	AuthentikServiceName string
	AuthentikServicePort int32
}

// Reconcile applies (or, if obj is being deleted or has opted out, tears
// down) the Authentik objects for one watched Ingress/HTTPRoute. It returns
// whether the caller should requeue with backoff (on error, controller-runtime
// does this automatically from the returned error; the bool is informational
// for validation failures that should NOT be retried).
func (s *Shared) Reconcile(ctx context.Context, obj client.Object, t *target.Target) error {
	logger := log.FromContext(ctx)

	spec, err := annotations.Parse(t.Name, t.Annotations)
	if err != nil {
		logger.Error(err, "invalid authentik.gddnet.io annotations, skipping")
		return nil
	}

	deleting := obj.GetDeletionTimestamp() != nil
	hasFinalizer := controllerutil.ContainsFinalizer(obj, annotations.FinalizerName)

	if deleting || !spec.Enabled {
		if !hasFinalizer {
			return nil
		}
		if err := s.Authentik.Cleanup(ctx, spec.Slug); err != nil {
			return fmt.Errorf("cleaning up authentik objects for %q: %w", spec.Slug, err)
		}
		// Best-effort: the proxy route's name is deterministic regardless of
		// mode, so this is a harmless no-op when mode was never "proxy".
		if err := s.deleteProxyRoute(ctx, t); err != nil {
			return err
		}
		controllerutil.RemoveFinalizer(obj, annotations.FinalizerName)
		return s.Client.Update(ctx, obj)
	}

	if !hasFinalizer {
		controllerutil.AddFinalizer(obj, annotations.FinalizerName)
		if err := s.Client.Update(ctx, obj); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}
	}

	var providerPK *int32
	switch spec.Mode {
	case annotations.ModeOAuth2:
		pk, err := s.applyOAuth2(ctx, t, spec)
		if err != nil {
			return err
		}
		providerPK = &pk
	case annotations.ModeProxy:
		pk, err := s.applyProxy(ctx, t, spec)
		if err != nil {
			return err
		}
		providerPK = &pk
	case annotations.ModeBlank:
		if err := s.deleteProxyRoute(ctx, t); err != nil {
			return err
		}
	}

	appPK, err := s.Authentik.UpsertApplication(ctx, authentik.ApplicationParams{
		Slug:         spec.Slug,
		Name:         spec.Name,
		Category:     spec.Category,
		Icon:         spec.Icon,
		Description:  spec.Description,
		Publisher:    spec.Publisher,
		OpenInNewTab: spec.OpenInNewTab,
		LaunchURL:    launchURL(t, spec),
		ProviderPK:   providerPK,
	})
	if err != nil {
		return fmt.Errorf("upserting application %q: %w", spec.Slug, err)
	}

	if err := s.Authentik.ReconcileGroupBindings(ctx, appPK, spec.AllowedGroups); err != nil {
		return fmt.Errorf("reconciling group bindings for %q: %w", spec.Slug, err)
	}

	return nil
}

func (s *Shared) applyOAuth2(ctx context.Context, t *target.Target, spec *annotations.Spec) (int32, error) {
	redirectURIs := spec.OAuth.RedirectURIs
	if len(redirectURIs) == 0 {
		if len(t.Hostnames) == 0 {
			return 0, fmt.Errorf("mode=oauth2 on %s/%s needs at least one hostname, or an explicit %s annotation", t.Namespace, t.Name, annotations.KeyOAuthRedirectURIs)
		}
		redirectURIs = []annotations.RedirectURI{annotations.DefaultOAuthRedirectURI(t.Hostnames[0])}
	}

	result, err := s.Authentik.UpsertOAuth2Provider(ctx, spec.Slug, redirectURIs, spec.OAuth.ClientType)
	if err != nil {
		return 0, fmt.Errorf("upserting oauth2 provider %q: %w", spec.Slug, err)
	}

	if err := s.syncOAuthSecret(ctx, t, spec, result); err != nil {
		return 0, err
	}

	return result.PK, nil
}

func (s *Shared) syncOAuthSecret(ctx context.Context, t *target.Target, spec *annotations.Spec, result *authentik.OAuth2ProviderResult) error {
	key := types.NamespacedName{Namespace: t.Namespace, Name: spec.OAuth.SecretName}
	stringData := map[string]string{
		spec.OAuth.ClientIDKey: result.ClientID,
		spec.OAuth.SecretKey:   result.ClientSecret,
	}

	var existing corev1.Secret
	err := s.Client.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            spec.OAuth.SecretName,
				Namespace:       t.Namespace,
				OwnerReferences: []metav1.OwnerReference{ownerRef(t)},
			},
			Type:       corev1.SecretTypeOpaque,
			StringData: stringData,
		}
		if err := s.Client.Create(ctx, secret); err != nil {
			return fmt.Errorf("creating secret %s/%s: %w", t.Namespace, spec.OAuth.SecretName, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting secret %s/%s: %w", t.Namespace, spec.OAuth.SecretName, err)
	}

	existing.OwnerReferences = []metav1.OwnerReference{ownerRef(t)}
	existing.Type = corev1.SecretTypeOpaque
	existing.StringData = stringData
	if err := s.Client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("updating secret %s/%s: %w", t.Namespace, spec.OAuth.SecretName, err)
	}
	return nil
}

func (s *Shared) applyProxy(ctx context.Context, t *target.Target, spec *annotations.Spec) (int32, error) {
	internalHost := spec.Proxy.InternalHost
	if internalHost == "" {
		internalHost = t.InternalHostURL()
	}
	if internalHost == "" {
		return 0, fmt.Errorf("mode=proxy on %s/%s needs %s (couldn't auto-derive a single backend Service+port)", t.Namespace, t.Name, annotations.KeyProxyInternalHost)
	}

	result, err := s.Authentik.UpsertProxyProvider(ctx, spec.Slug, "https://"+spec.Proxy.Hostname, internalHost, spec.Proxy.Mode)
	if err != nil {
		return 0, fmt.Errorf("upserting proxy provider %q: %w", spec.Slug, err)
	}

	if err := s.Authentik.AddProviderToEmbeddedOutpost(ctx, result.PK); err != nil {
		return 0, fmt.Errorf("adding proxy provider %q to embedded outpost: %w", spec.Slug, err)
	}

	if err := s.syncProxyRoute(ctx, t, spec); err != nil {
		return 0, err
	}

	return result.PK, nil
}

// proxyRouteName is deterministic and namespace-qualified so routes from
// different source namespaces (all living together in AuthentikNamespace)
// never collide.
func proxyRouteName(t *target.Target) string {
	return fmt.Sprintf("%s-%s-authentik-proxy", t.Namespace, t.Name)
}

func (s *Shared) syncProxyRoute(ctx context.Context, t *target.Target, spec *annotations.Spec) error {
	pathPrefix := gatewayv1.PathMatchPathPrefix
	pathValue := "/"
	port := gatewayv1.PortNumber(s.AuthentikServicePort)
	group := gatewayv1.Group("gateway.networking.k8s.io")
	kind := gatewayv1.Kind("Gateway")
	ns := gatewayv1.Namespace(s.Gateway.Namespace)
	section := gatewayv1.SectionName(s.Gateway.SectionName)

	desiredSpec := gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{
			ParentRefs: []gatewayv1.ParentReference{{
				Group:       &group,
				Kind:        &kind,
				Name:        gatewayv1.ObjectName(s.Gateway.Name),
				Namespace:   &ns,
				SectionName: &section,
			}},
		},
		Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(spec.Proxy.Hostname)},
		Rules: []gatewayv1.HTTPRouteRule{{
			Matches: []gatewayv1.HTTPRouteMatch{{
				Path: &gatewayv1.HTTPPathMatch{Type: &pathPrefix, Value: &pathValue},
			}},
			BackendRefs: []gatewayv1.HTTPBackendRef{{
				BackendRef: gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: gatewayv1.ObjectName(s.AuthentikServiceName),
						Port: &port,
					},
				},
			}},
		}},
	}

	key := types.NamespacedName{Namespace: s.AuthentikNamespace, Name: proxyRouteName(t)}
	var existing gatewayv1.HTTPRoute
	err := s.Client.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		route := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      key.Name,
				Namespace: key.Namespace,
			},
			Spec: desiredSpec,
		}
		if err := s.Client.Create(ctx, route); err != nil {
			return fmt.Errorf("creating proxy route %s/%s: %w", key.Namespace, key.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting proxy route %s/%s: %w", key.Namespace, key.Name, err)
	}

	existing.Spec = desiredSpec
	if err := s.Client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("updating proxy route %s/%s: %w", key.Namespace, key.Name, err)
	}
	return nil
}

func (s *Shared) deleteProxyRoute(ctx context.Context, t *target.Target) error {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      proxyRouteName(t),
			Namespace: s.AuthentikNamespace,
		},
	}
	if err := s.Client.Delete(ctx, route); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting proxy route %s/%s: %w", s.AuthentikNamespace, route.Name, err)
	}
	return nil
}

// launchURL resolves the Application's launch URL: an explicit
// authentik.gddnet.io/url annotation always wins; otherwise it's derived per
// mode so app tiles are clickable without any extra configuration.
func launchURL(t *target.Target, spec *annotations.Spec) string {
	if spec.URL != "" {
		return spec.URL
	}
	switch spec.Mode {
	case annotations.ModeProxy:
		// The resource's own hostname is often Tailscale-only (that's the
		// whole point of proxy mode); the proxy hostname is what's actually
		// publicly reachable.
		return annotations.DefaultLaunchURL(spec.Proxy.Hostname)
	default:
		if len(t.Hostnames) > 0 {
			return annotations.DefaultLaunchURL(t.Hostnames[0])
		}
		return ""
	}
}

func ownerRef(t *target.Target) metav1.OwnerReference {
	apiVersion, kind := "networking.k8s.io/v1", "Ingress"
	if t.Kind == target.KindHTTPRoute {
		apiVersion, kind = "gateway.networking.k8s.io/v1", "HTTPRoute"
	}
	isController := true
	return metav1.OwnerReference{
		APIVersion:         apiVersion,
		Kind:               kind,
		Name:               t.Name,
		UID:                t.UID,
		Controller:         &isController,
		BlockOwnerDeletion: &isController,
	}
}
