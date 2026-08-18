package annotations

import "testing"

func TestParse_Disabled(t *testing.T) {
	s, err := Parse("myapp", map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Enabled {
		t.Fatalf("expected Enabled=false when annotation absent")
	}
	if s.Slug != "myapp" {
		t.Fatalf("expected Slug to default to resource name even when disabled, got %q", s.Slug)
	}
}

func TestParse_Blank(t *testing.T) {
	s, err := Parse("myapp", map[string]string{
		KeyEnabled:  "true",
		KeyMode:     "blank",
		KeyCategory: "Media",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.Enabled || s.Mode != ModeBlank || s.Category != "Media" {
		t.Fatalf("unexpected spec: %+v", s)
	}
}

func TestParse_MissingMode(t *testing.T) {
	_, err := Parse("myapp", map[string]string{KeyEnabled: "true"})
	if err == nil {
		t.Fatalf("expected error when mode is missing")
	}
}

func TestParse_OAuth2Defaults(t *testing.T) {
	s, err := Parse("myapp", map[string]string{
		KeyEnabled: "true",
		KeyMode:    "oauth2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.OAuth.ClientType != "confidential" {
		t.Fatalf("expected default client type confidential, got %q", s.OAuth.ClientType)
	}
	if s.OAuth.SecretName != "myapp-authentik-oauth" {
		t.Fatalf("expected default secret name, got %q", s.OAuth.SecretName)
	}
	if len(s.OAuth.RedirectURIs) != 0 {
		t.Fatalf("expected no redirect URIs when unset (caller defaults from hostname), got %v", s.OAuth.RedirectURIs)
	}
}

func TestParse_ProxyRequiresHostname(t *testing.T) {
	_, err := Parse("myapp", map[string]string{
		KeyEnabled: "true",
		KeyMode:    "proxy",
	})
	if err == nil {
		t.Fatalf("expected error when proxy-hostname is missing")
	}

	s, err := Parse("myapp", map[string]string{
		KeyEnabled:       "true",
		KeyMode:          "proxy",
		KeyProxyHostname: "myapp.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Proxy.Mode != "proxy" {
		t.Fatalf("expected default proxy mode 'proxy', got %q", s.Proxy.Mode)
	}
}

func TestParse_AllowedGroupsSplit(t *testing.T) {
	s, err := Parse("myapp", map[string]string{
		KeyEnabled:       "true",
		KeyMode:          "blank",
		KeyAllowedGroups: "admins, editors ,viewers",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"admins", "editors", "viewers"}
	if len(s.AllowedGroups) != len(want) {
		t.Fatalf("expected %v, got %v", want, s.AllowedGroups)
	}
	for i, g := range want {
		if s.AllowedGroups[i] != g {
			t.Fatalf("expected %v, got %v", want, s.AllowedGroups)
		}
	}
}
