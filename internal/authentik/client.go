// Package authentik wraps the parts of goauthentik.io/api/v3 the operator
// needs: upserting Applications and OAuth2/Proxy Providers by name, resolving
// Groups, reconciling access-restriction PolicyBindings, and keeping the
// embedded outpost's provider list in sync for proxy mode.
package authentik

import (
	"context"
	"fmt"
	"sync"

	api "goauthentik.io/api/v3"

	"github.com/negativefeedback/authentik-operator/internal/annotations"
)

const embeddedOutpostName = "authentik Embedded Outpost"

// Flow slugs proven working in this environment's Terraform config
// (terraform/homeops/authentik-app.tf) — kept identical so operator-created
// and Terraform-created providers behave the same way.
const (
	AuthorizationFlowSlug = "default-provider-authorization-implicit-consent"
	InvalidationFlowSlug  = "default-provider-invalidation-flow"
)

// DefaultSigningKeyName is the certificate Authentik provisions on install
// and defaults to when creating an OAuth2 Provider through its own UI.
// Without an explicit signing_key, Authentik has no RSA key to publish, so
// /jwks/ serves `{}` (no "keys" field at all) instead of a real key set —
// OIDC client libraries that parse the ID token's JWKS (authlib, used by
// Open WebUI, among others) then fail with "Invalid key set format".
const DefaultSigningKeyName = "authentik Self-signed Certificate"

// defaultOAuth2ScopeMappings are the built-in Scope Mappings Authentik's own
// UI wizard attaches automatically when creating an OAuth2 Provider. Without
// them, the provider has zero grantable scopes: the access token comes back
// with an empty scope set no matter what the client requested, and anything
// scope-gated (like /userinfo/) 403s.
var defaultOAuth2ScopeMappings = []string{
	"goauthentik.io/providers/oauth2/scope-openid",
	"goauthentik.io/providers/oauth2/scope-email",
	"goauthentik.io/providers/oauth2/scope-profile",
}

type Client struct {
	api   *api.APIClient
	token string

	mu                  sync.Mutex
	flowCache           map[string]string
	signingKeyPKOnce    string
	scopeMappingPKsOnce []string
}

func New(baseURL, token string) *Client {
	cfg := api.NewConfiguration()
	cfg.Servers = api.ServerConfigurations{{URL: baseURL + "/api/v3"}}
	return &Client{
		api:       api.NewAPIClient(cfg),
		token:     token,
		flowCache: make(map[string]string),
	}
}

func (c *Client) authCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, api.ContextAccessToken, c.token)
}

func (c *Client) flowPK(ctx context.Context, slug string) (string, error) {
	c.mu.Lock()
	if pk, ok := c.flowCache[slug]; ok {
		c.mu.Unlock()
		return pk, nil
	}
	c.mu.Unlock()

	resp, _, err := c.api.FlowsAPI.FlowsInstancesList(c.authCtx(ctx)).Slug(slug).Execute()
	if err != nil {
		return "", fmt.Errorf("looking up flow %q: %w", slug, err)
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("flow %q not found", slug)
	}
	pk := resp.Results[0].Pk

	c.mu.Lock()
	c.flowCache[slug] = pk
	c.mu.Unlock()
	return pk, nil
}

func (c *Client) signingKeyPK(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.signingKeyPKOnce != "" {
		pk := c.signingKeyPKOnce
		c.mu.Unlock()
		return pk, nil
	}
	c.mu.Unlock()

	resp, _, err := c.api.CryptoAPI.CryptoCertificatekeypairsList(c.authCtx(ctx)).Name(DefaultSigningKeyName).Execute()
	if err != nil {
		return "", fmt.Errorf("looking up signing key %q: %w", DefaultSigningKeyName, err)
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("signing key %q not found", DefaultSigningKeyName)
	}
	pk := resp.Results[0].Pk

	c.mu.Lock()
	c.signingKeyPKOnce = pk
	c.mu.Unlock()
	return pk, nil
}

func (c *Client) defaultScopeMappingPKs(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	if c.scopeMappingPKsOnce != nil {
		pks := c.scopeMappingPKsOnce
		c.mu.Unlock()
		return pks, nil
	}
	c.mu.Unlock()

	resp, _, err := c.api.PropertymappingsAPI.PropertymappingsProviderScopeList(c.authCtx(ctx)).Managed(defaultOAuth2ScopeMappings).Execute()
	if err != nil {
		return nil, fmt.Errorf("looking up default scope mappings: %w", err)
	}
	if len(resp.Results) != len(defaultOAuth2ScopeMappings) {
		return nil, fmt.Errorf("expected %d default scope mappings, found %d", len(defaultOAuth2ScopeMappings), len(resp.Results))
	}
	pks := make([]string, len(resp.Results))
	for i, m := range resp.Results {
		pks[i] = m.Pk
	}

	c.mu.Lock()
	c.scopeMappingPKsOnce = pks
	c.mu.Unlock()
	return pks, nil
}

// ApplicationParams is the desired state of an Authentik Application.
type ApplicationParams struct {
	Slug         string
	Name         string
	Category     string
	Icon         string
	Description  string
	Publisher    string
	LaunchURL    string
	OpenInNewTab bool
	// ProviderPK is nil for blank-mode applications.
	ProviderPK *int32
}

// UpsertApplication creates or updates the Application with the given slug,
// returning its (string) primary key.
func (c *Client) UpsertApplication(ctx context.Context, p ApplicationParams) (string, error) {
	ctx = c.authCtx(ctx)

	_, _, err := c.api.CoreAPI.CoreApplicationsRetrieve(ctx, p.Slug).Execute()
	if err != nil {
		req := api.ApplicationRequest{
			Name: p.Name,
			Slug: p.Slug,
		}
		applyApplicationOptional(&req, p)
		created, _, cerr := c.api.CoreAPI.CoreApplicationsCreate(ctx).ApplicationRequest(req).Execute()
		if cerr != nil {
			return "", fmt.Errorf("creating application %q: %w", p.Slug, cerr)
		}
		return created.Pk, nil
	}

	patch := api.PatchedApplicationRequest{
		Name: &p.Name,
	}
	applyPatchedApplicationOptional(&patch, p)
	updated, _, err := c.api.CoreAPI.CoreApplicationsPartialUpdate(ctx, p.Slug).PatchedApplicationRequest(patch).Execute()
	if err != nil {
		return "", fmt.Errorf("updating application %q: %w", p.Slug, err)
	}
	return updated.Pk, nil
}

func applyApplicationOptional(req *api.ApplicationRequest, p ApplicationParams) {
	if p.Category != "" {
		req.Group = &p.Category
	}
	if p.Icon != "" {
		req.MetaIcon = &p.Icon
	}
	if p.Description != "" {
		req.MetaDescription = &p.Description
	}
	if p.Publisher != "" {
		req.MetaPublisher = &p.Publisher
	}
	if p.LaunchURL != "" {
		req.MetaLaunchUrl = &p.LaunchURL
	}
	req.OpenInNewTab = &p.OpenInNewTab
	if p.ProviderPK != nil {
		req.SetProvider(*p.ProviderPK)
	} else {
		req.SetProviderNil()
	}
}

func applyPatchedApplicationOptional(req *api.PatchedApplicationRequest, p ApplicationParams) {
	if p.Category != "" {
		req.Group = &p.Category
	}
	if p.Icon != "" {
		req.MetaIcon = &p.Icon
	}
	if p.Description != "" {
		req.MetaDescription = &p.Description
	}
	if p.Publisher != "" {
		req.MetaPublisher = &p.Publisher
	}
	if p.LaunchURL != "" {
		req.MetaLaunchUrl = &p.LaunchURL
	}
	req.OpenInNewTab = &p.OpenInNewTab
	if p.ProviderPK != nil {
		req.SetProvider(*p.ProviderPK)
	} else {
		req.SetProviderNil()
	}
}

// DeleteApplication removes the Application with the given slug, if present.
func (c *Client) DeleteApplication(ctx context.Context, slug string) error {
	ctx = c.authCtx(ctx)
	if _, _, err := c.api.CoreAPI.CoreApplicationsRetrieve(ctx, slug).Execute(); err != nil {
		return nil // already gone
	}
	_, err := c.api.CoreAPI.CoreApplicationsDestroy(ctx, slug).Execute()
	if err != nil {
		return fmt.Errorf("deleting application %q: %w", slug, err)
	}
	return nil
}

// OAuth2ProviderResult is the caller-relevant subset of an upserted OAuth2Provider.
type OAuth2ProviderResult struct {
	PK           int32
	ClientID     string
	ClientSecret string
}

// UpsertOAuth2Provider creates or updates an OAuth2 Provider named name.
// Client id/secret are left to authentik to generate/preserve; the resulting
// (possibly pre-existing) credentials are returned so the caller can sync
// them into a Kubernetes Secret.
func (c *Client) UpsertOAuth2Provider(ctx context.Context, name string, redirectURIs []annotations.RedirectURI, clientType string) (*OAuth2ProviderResult, error) {
	ctx = c.authCtx(ctx)

	authFlow, err := c.flowPK(ctx, AuthorizationFlowSlug)
	if err != nil {
		return nil, err
	}
	invFlow, err := c.flowPK(ctx, InvalidationFlowSlug)
	if err != nil {
		return nil, err
	}
	signingKey, err := c.signingKeyPK(ctx)
	if err != nil {
		return nil, err
	}
	scopeMappings, err := c.defaultScopeMappingPKs(ctx)
	if err != nil {
		return nil, err
	}

	uris := toRedirectURIRequests(redirectURIs)
	ct := api.ClientTypeEnum(clientType)
	// Authentik doesn't default this to anything usable via the API (unlike
	// the UI wizard): leaving it unset creates a provider that rejects the
	// authorization_code flow entirely ("Invalid grant_type for provider" at
	// the /authorize/ endpoint).
	grantTypes := []api.GrantTypesEnum{api.GRANTTYPESENUM_AUTHORIZATION_CODE, api.GRANTTYPESENUM_REFRESH_TOKEN}

	existing, err := c.findOAuth2ProviderByName(ctx, name)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		req := api.OAuth2ProviderRequest{
			Name:              name,
			AuthorizationFlow: authFlow,
			InvalidationFlow:  invFlow,
			ClientType:        &ct,
			GrantTypes:        grantTypes,
			PropertyMappings:  scopeMappings,
			RedirectUris:      uris,
		}
		req.SetSigningKey(signingKey)
		created, _, err := c.api.ProvidersAPI.ProvidersOauth2Create(ctx).OAuth2ProviderRequest(req).Execute()
		if err != nil {
			return nil, fmt.Errorf("creating oauth2 provider %q: %w", name, err)
		}
		return &OAuth2ProviderResult{PK: created.Pk, ClientID: created.GetClientId(), ClientSecret: created.GetClientSecret()}, nil
	}

	patch := api.PatchedOAuth2ProviderRequest{
		Name:              &name,
		AuthorizationFlow: &authFlow,
		InvalidationFlow:  &invFlow,
		ClientType:        &ct,
		GrantTypes:        grantTypes,
		PropertyMappings:  scopeMappings,
		RedirectUris:      uris,
	}
	patch.SetSigningKey(signingKey)
	updated, _, err := c.api.ProvidersAPI.ProvidersOauth2PartialUpdate(ctx, existing.Pk).PatchedOAuth2ProviderRequest(patch).Execute()
	if err != nil {
		return nil, fmt.Errorf("updating oauth2 provider %q: %w", name, err)
	}
	return &OAuth2ProviderResult{PK: updated.Pk, ClientID: updated.GetClientId(), ClientSecret: updated.GetClientSecret()}, nil
}

func (c *Client) findOAuth2ProviderByName(ctx context.Context, name string) (*api.OAuth2Provider, error) {
	resp, _, err := c.api.ProvidersAPI.ProvidersOauth2List(ctx).Name(name).Execute()
	if err != nil {
		return nil, fmt.Errorf("looking up oauth2 provider %q: %w", name, err)
	}
	if len(resp.Results) == 0 {
		return nil, nil
	}
	return &resp.Results[0], nil
}

// DeleteOAuth2Provider removes the OAuth2 Provider named name, if present.
func (c *Client) DeleteOAuth2Provider(ctx context.Context, name string) error {
	ctx = c.authCtx(ctx)
	existing, err := c.findOAuth2ProviderByName(ctx, name)
	if err != nil || existing == nil {
		return err
	}
	if _, err := c.api.ProvidersAPI.ProvidersOauth2Destroy(ctx, existing.Pk).Execute(); err != nil {
		return fmt.Errorf("deleting oauth2 provider %q: %w", name, err)
	}
	return nil
}

func toRedirectURIRequests(uris []annotations.RedirectURI) []api.RedirectURIRequest {
	out := make([]api.RedirectURIRequest, 0, len(uris))
	for _, u := range uris {
		mode := api.MATCHINGMODEENUM_STRICT
		if u.MatchingMode == "regex" {
			mode = api.MATCHINGMODEENUM_REGEX
		}
		out = append(out, api.RedirectURIRequest{MatchingMode: mode, Url: u.URL})
	}
	return out
}

// ProxyProviderResult is the caller-relevant subset of an upserted ProxyProvider.
type ProxyProviderResult struct {
	PK int32
}

// UpsertProxyProvider creates or updates a Proxy Provider named name.
func (c *Client) UpsertProxyProvider(ctx context.Context, name, externalHost, internalHost, mode string) (*ProxyProviderResult, error) {
	ctx = c.authCtx(ctx)

	authFlow, err := c.flowPK(ctx, AuthorizationFlowSlug)
	if err != nil {
		return nil, err
	}
	invFlow, err := c.flowPK(ctx, InvalidationFlowSlug)
	if err != nil {
		return nil, err
	}

	pm := api.ProxyMode(mode)
	existing, err := c.findProxyProviderByName(ctx, name)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		req := api.ProxyProviderRequest{
			Name:              name,
			AuthorizationFlow: authFlow,
			InvalidationFlow:  invFlow,
			ExternalHost:      externalHost,
			InternalHost:      &internalHost,
			Mode:              &pm,
		}
		created, _, err := c.api.ProvidersAPI.ProvidersProxyCreate(ctx).ProxyProviderRequest(req).Execute()
		if err != nil {
			return nil, fmt.Errorf("creating proxy provider %q: %w", name, err)
		}
		return &ProxyProviderResult{PK: created.Pk}, nil
	}

	patch := api.PatchedProxyProviderRequest{
		Name:              &name,
		AuthorizationFlow: &authFlow,
		InvalidationFlow:  &invFlow,
		ExternalHost:      &externalHost,
		InternalHost:      &internalHost,
		Mode:              &pm,
	}
	updated, _, err := c.api.ProvidersAPI.ProvidersProxyPartialUpdate(ctx, existing.Pk).PatchedProxyProviderRequest(patch).Execute()
	if err != nil {
		return nil, fmt.Errorf("updating proxy provider %q: %w", name, err)
	}
	return &ProxyProviderResult{PK: updated.Pk}, nil
}

func (c *Client) findProxyProviderByName(ctx context.Context, name string) (*api.ProxyProvider, error) {
	resp, _, err := c.api.ProvidersAPI.ProvidersProxyList(ctx).NameIexact(name).Execute()
	if err != nil {
		return nil, fmt.Errorf("looking up proxy provider %q: %w", name, err)
	}
	if len(resp.Results) == 0 {
		return nil, nil
	}
	return &resp.Results[0], nil
}

// DeleteProxyProvider removes the Proxy Provider named name, if present.
func (c *Client) DeleteProxyProvider(ctx context.Context, name string) error {
	ctx = c.authCtx(ctx)
	existing, err := c.findProxyProviderByName(ctx, name)
	if err != nil || existing == nil {
		return err
	}
	if _, err := c.api.ProvidersAPI.ProvidersProxyDestroy(ctx, existing.Pk).Execute(); err != nil {
		return fmt.Errorf("deleting proxy provider %q: %w", name, err)
	}
	return nil
}

// GroupPKByName resolves an Authentik Group's primary key by its display name.
func (c *Client) GroupPKByName(ctx context.Context, name string) (string, error) {
	ctx = c.authCtx(ctx)
	resp, _, err := c.api.CoreAPI.CoreGroupsList(ctx).Name(name).Execute()
	if err != nil {
		return "", fmt.Errorf("looking up group %q: %w", name, err)
	}
	if len(resp.Results) == 0 {
		return "", fmt.Errorf("group %q not found in authentik", name)
	}
	return resp.Results[0].Pk, nil
}

// ReconcileGroupBindings makes the set of group-type PolicyBindings on the
// Application identified by applicationPK match groupNames exactly. Only
// group-type bindings are touched; any policy- or user-type bindings a human
// added directly are left alone.
func (c *Client) ReconcileGroupBindings(ctx context.Context, applicationPK string, groupNames []string) error {
	ctx = c.authCtx(ctx)

	desired := make(map[string]bool, len(groupNames))
	for _, name := range groupNames {
		pk, err := c.GroupPKByName(ctx, name)
		if err != nil {
			return err
		}
		desired[pk] = true
	}

	resp, _, err := c.api.PoliciesAPI.PoliciesBindingsList(ctx).Target(applicationPK).Execute()
	if err != nil {
		return fmt.Errorf("listing policy bindings for %q: %w", applicationPK, err)
	}

	existingByGroup := make(map[string]string) // group pk -> binding pk
	for _, b := range resp.Results {
		if !b.Group.IsSet() || b.Group.Get() == nil {
			continue // not a group-type binding; leave it alone
		}
		existingByGroup[*b.Group.Get()] = b.Pk
	}

	for groupPK := range desired {
		if _, ok := existingByGroup[groupPK]; ok {
			continue
		}
		req := api.PolicyBindingRequest{
			Target: applicationPK,
			Group:  *api.NewNullableString(&groupPK),
			Order:  0,
		}
		if _, _, err := c.api.PoliciesAPI.PoliciesBindingsCreate(ctx).PolicyBindingRequest(req).Execute(); err != nil {
			return fmt.Errorf("binding group %q to %q: %w", groupPK, applicationPK, err)
		}
	}

	for groupPK, bindingPK := range existingByGroup {
		if desired[groupPK] {
			continue
		}
		if _, err := c.api.PoliciesAPI.PoliciesBindingsDestroy(ctx, bindingPK).Execute(); err != nil {
			return fmt.Errorf("unbinding group %q from %q: %w", groupPK, applicationPK, err)
		}
	}

	return nil
}

// DeleteAllGroupBindings removes every group-type PolicyBinding on the
// Application, used during finalizer cleanup.
func (c *Client) DeleteAllGroupBindings(ctx context.Context, applicationPK string) error {
	return c.ReconcileGroupBindings(ctx, applicationPK, nil)
}

func (c *Client) embeddedOutpost(ctx context.Context) (*api.Outpost, error) {
	resp, _, err := c.api.OutpostsAPI.OutpostsInstancesList(ctx).NameIexact(embeddedOutpostName).Execute()
	if err != nil {
		return nil, fmt.Errorf("looking up embedded outpost: %w", err)
	}
	if len(resp.Results) == 0 {
		return nil, fmt.Errorf("embedded outpost %q not found", embeddedOutpostName)
	}
	return &resp.Results[0], nil
}

// AddProviderToEmbeddedOutpost ensures providerPK is a member of the
// embedded outpost's provider list.
func (c *Client) AddProviderToEmbeddedOutpost(ctx context.Context, providerPK int32) error {
	ctx = c.authCtx(ctx)
	outpost, err := c.embeddedOutpost(ctx)
	if err != nil {
		return err
	}
	for _, pk := range outpost.Providers {
		if pk == providerPK {
			return nil // already a member
		}
	}
	providers := append(append([]int32{}, outpost.Providers...), providerPK)
	patch := api.PatchedOutpostRequest{Providers: providers}
	if _, _, err := c.api.OutpostsAPI.OutpostsInstancesPartialUpdate(ctx, outpost.Pk).PatchedOutpostRequest(patch).Execute(); err != nil {
		return fmt.Errorf("adding provider %d to embedded outpost: %w", providerPK, err)
	}
	return nil
}

// Cleanup removes every Authentik object the operator may have created for
// the application identified by slug: group PolicyBindings, embedded-outpost
// membership, both provider kinds (looked up by the same name=slug
// convention used by Upsert*), and the Application itself. Safe to call even
// if some or all of these were never created.
func (c *Client) Cleanup(ctx context.Context, slug string) error {
	authedCtx := c.authCtx(ctx)

	if app, _, err := c.api.CoreAPI.CoreApplicationsRetrieve(authedCtx, slug).Execute(); err == nil && app != nil {
		if err := c.ReconcileGroupBindings(ctx, app.Pk, nil); err != nil {
			return err
		}
	}

	if proxy, err := c.findProxyProviderByName(authedCtx, slug); err == nil && proxy != nil {
		if err := c.RemoveProviderFromEmbeddedOutpost(ctx, proxy.Pk); err != nil {
			return err
		}
	}

	if err := c.DeleteOAuth2Provider(ctx, slug); err != nil {
		return err
	}
	if err := c.DeleteProxyProvider(ctx, slug); err != nil {
		return err
	}
	return c.DeleteApplication(ctx, slug)
}

// RemoveProviderFromEmbeddedOutpost removes providerPK from the embedded
// outpost's provider list, if present.
func (c *Client) RemoveProviderFromEmbeddedOutpost(ctx context.Context, providerPK int32) error {
	ctx = c.authCtx(ctx)
	outpost, err := c.embeddedOutpost(ctx)
	if err != nil {
		return err
	}
	providers := make([]int32, 0, len(outpost.Providers))
	found := false
	for _, pk := range outpost.Providers {
		if pk == providerPK {
			found = true
			continue
		}
		providers = append(providers, pk)
	}
	if !found {
		return nil
	}
	patch := api.PatchedOutpostRequest{Providers: providers}
	if _, _, err := c.api.OutpostsAPI.OutpostsInstancesPartialUpdate(ctx, outpost.Pk).PatchedOutpostRequest(patch).Execute(); err != nil {
		return fmt.Errorf("removing provider %d from embedded outpost: %w", providerPK, err)
	}
	return nil
}
