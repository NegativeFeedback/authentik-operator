// Package annotations parses the authentik.gddnet.io/* annotation schema that
// drives the operator off of Ingress and HTTPRoute objects.
package annotations

import (
	"fmt"
	"strconv"
	"strings"
)

const Prefix = "authentik.gddnet.io/"

const (
	KeyEnabled       = Prefix + "enabled"
	KeyMode          = Prefix + "mode"
	KeyName          = Prefix + "name"
	KeySlug          = Prefix + "slug"
	KeyCategory      = Prefix + "category"
	KeyIcon          = Prefix + "icon"
	KeyDescription   = Prefix + "description"
	KeyURL           = Prefix + "url"
	KeyPublisher     = Prefix + "publisher"
	KeyOpenInNewTab  = Prefix + "open-in-new-tab"
	KeyAllowedGroups = Prefix + "allowed-groups"

	KeyOAuthRedirectURIs = Prefix + "oauth-redirect-uris"
	KeyOAuthClientType   = Prefix + "oauth-client-type"
	KeyOAuthSecretName   = Prefix + "oauth-secret-name"
	KeyOAuthSecretKeys   = Prefix + "oauth-secret-keys"

	KeyProxyHostname     = Prefix + "proxy-hostname"
	KeyProxyInternalHost = Prefix + "proxy-internal-host"
	KeyProxyMode         = Prefix + "proxy-mode"

	FinalizerName = Prefix + "finalizer"
)

type Mode string

const (
	ModeBlank  Mode = "blank"
	ModeOAuth2 Mode = "oauth2"
	ModeProxy  Mode = "proxy"
)

// RedirectURI mirrors authentik's RedirectURIRequest shape without importing
// the API client into this package.
type RedirectURI struct {
	MatchingMode string // "strict" or "regex"
	URL          string
}

type OAuthSpec struct {
	RedirectURIs []RedirectURI
	ClientType   string // "confidential" or "public"
	SecretName   string
	ClientIDKey  string
	SecretKey    string
}

type ProxySpec struct {
	Hostname     string
	InternalHost string
	Mode         string // "proxy", "forward_single", "forward_domain"
}

// Spec is the parsed, defaulted, and validated form of the annotation set on
// a single Ingress or HTTPRoute.
type Spec struct {
	Enabled      bool
	Mode         Mode
	Name         string
	Slug         string
	Category     string
	Icon         string
	Description  string
	Publisher    string
	OpenInNewTab bool
	// URL is the explicit launch URL override (authentik.gddnet.io/url). When
	// empty, the caller derives a sane per-mode default from the resource's
	// hostnames (see reconcile.go) rather than leaving the app tile
	// unclickable.
	URL           string
	AllowedGroups []string

	OAuth OAuthSpec
	Proxy ProxySpec
}

// Parse extracts and validates a Spec from an object's annotations.
// resourceName is used as the default for Name/Slug/OAuth secret name.
// Enabled is false (with no error) when the resource has opted out or was
// never opted in, which callers should treat as "nothing to do here".
func Parse(resourceName string, ann map[string]string) (*Spec, error) {
	enabled, _ := strconv.ParseBool(ann[KeyEnabled])

	// Slug is resolved unconditionally (even when disabled) so callers can
	// still identify which Authentik objects to clean up after the user
	// flips authentik.gddnet.io/enabled to false without deleting the
	// resource itself.
	slug := defaultString(ann[KeySlug], resourceName)
	if !enabled {
		return &Spec{Enabled: false, Slug: slug}, nil
	}

	openInNewTab, _ := strconv.ParseBool(ann[KeyOpenInNewTab])
	s := &Spec{
		Enabled:      true,
		Mode:         Mode(ann[KeyMode]),
		Name:         defaultString(ann[KeyName], resourceName),
		Slug:         slug,
		Category:     ann[KeyCategory],
		Icon:         ann[KeyIcon],
		Description:  ann[KeyDescription],
		Publisher:    ann[KeyPublisher],
		OpenInNewTab: openInNewTab,
		URL:          ann[KeyURL],
	}

	switch s.Mode {
	case ModeBlank, ModeOAuth2, ModeProxy:
	case "":
		return nil, fmt.Errorf("%s is required when %s=true", KeyMode, KeyEnabled)
	default:
		return nil, fmt.Errorf("%s: unsupported value %q (want blank, oauth2, or proxy)", KeyMode, s.Mode)
	}

	if v := ann[KeyAllowedGroups]; v != "" {
		s.AllowedGroups = splitTrim(v)
	}

	if s.Mode == ModeOAuth2 {
		oauth, err := parseOAuth(resourceName, ann)
		if err != nil {
			return nil, err
		}
		s.OAuth = *oauth
	}

	if s.Mode == ModeProxy {
		proxy, err := parseProxy(ann)
		if err != nil {
			return nil, err
		}
		s.Proxy = *proxy
	}

	return s, nil
}

func parseOAuth(resourceName string, ann map[string]string) (*OAuthSpec, error) {
	o := &OAuthSpec{
		ClientType:  defaultString(ann[KeyOAuthClientType], "confidential"),
		SecretName:  defaultString(ann[KeyOAuthSecretName], resourceName+"-authentik-oauth"),
		ClientIDKey: "CLIENT_ID",
		SecretKey:   "CLIENT_SECRET",
	}

	if o.ClientType != "confidential" && o.ClientType != "public" {
		return nil, fmt.Errorf("%s: unsupported value %q (want confidential or public)", KeyOAuthClientType, o.ClientType)
	}

	if v := ann[KeyOAuthSecretKeys]; v != "" {
		parts := splitTrim(v)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s: want exactly two comma-separated keys (client-id,client-secret), got %q", KeyOAuthSecretKeys, v)
		}
		o.ClientIDKey, o.SecretKey = parts[0], parts[1]
	}

	if v := ann[KeyOAuthRedirectURIs]; v != "" {
		for _, u := range splitTrim(v) {
			o.RedirectURIs = append(o.RedirectURIs, RedirectURI{MatchingMode: "strict", URL: u})
		}
	}
	// If no explicit redirect URIs were given, the caller (which knows the
	// resource's hostnames) fills in a permissive regex default.

	return o, nil
}

func parseProxy(ann map[string]string) (*ProxySpec, error) {
	p := &ProxySpec{
		Hostname:     ann[KeyProxyHostname],
		InternalHost: ann[KeyProxyInternalHost],
		Mode:         defaultString(ann[KeyProxyMode], "proxy"),
	}

	if p.Hostname == "" {
		return nil, fmt.Errorf("%s is required for mode=proxy", KeyProxyHostname)
	}

	switch p.Mode {
	case "proxy", "forward_single", "forward_domain":
	default:
		return nil, fmt.Errorf("%s: unsupported value %q (want proxy, forward_single, or forward_domain)", KeyProxyMode, p.Mode)
	}

	return p, nil
}

// DefaultOAuthRedirectURI builds the zero-config fallback redirect URI for a
// hostname when the user didn't specify authentik.gddnet.io/oauth-redirect-uris.
func DefaultOAuthRedirectURI(hostname string) RedirectURI {
	return RedirectURI{MatchingMode: "regex", URL: fmt.Sprintf("https://%s/.*", hostname)}
}

// DefaultLaunchURL builds the zero-config fallback launch URL for a hostname
// when the user didn't specify authentik.gddnet.io/url, so app tiles are
// clickable out of the box.
func DefaultLaunchURL(hostname string) string {
	return fmt.Sprintf("https://%s/", hostname)
}

func defaultString(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func splitTrim(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
