package config

import (
	"strings"
	"testing"
)

// setRequired sets the mandatory variables to valid values.
func setRequired(t *testing.T) {
	t.Setenv("KEYCLOAK_ISSUER", "http://localhost:8080/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "portal")
	t.Setenv("OIDC_CLIENT_SECRET", "shh")
	t.Setenv("PEAT_NODE_ADDR", "localhost:50051")
}

// clearAll blanks every variable Load reads, so a test starts from a known
// state regardless of the ambient environment.
func clearAll(t *testing.T) {
	for _, k := range []string{
		"LISTEN_ADDR", "KEYCLOAK_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
		"OIDC_REDIRECT_URL", "OIDC_POST_LOGOUT_REDIRECT_URL", "OIDC_SCOPES", "COOKIE_SECURE",
		"PEAT_NODE_ADDR", "PEAT_COLLECTION", "PEAT_TLS",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadMissingRequired(t *testing.T) {
	clearAll(t)
	_, err := Load()
	if err == nil {
		t.Fatal("expected error when required vars are missing")
	}
	for _, want := range []string{"KEYCLOAK_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "PEAT_NODE_ADDR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearAll(t)
	setRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":3000" {
		t.Errorf("ListenAddr = %q, want :3000", cfg.ListenAddr)
	}
	if cfg.RedirectURL != "http://localhost:3000/auth/callback" {
		t.Errorf("RedirectURL = %q", cfg.RedirectURL)
	}
	if cfg.PostLogoutRedirectURL != "http://localhost:3000/" {
		t.Errorf("PostLogoutRedirectURL = %q", cfg.PostLogoutRedirectURL)
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure should default to false")
	}
	wantScopes := []string{"openid", "profile", "email", "roles"}
	if strings.Join(cfg.Scopes, " ") != strings.Join(wantScopes, " ") {
		t.Errorf("Scopes = %v, want %v", cfg.Scopes, wantScopes)
	}
	if cfg.PeatCollection != "data_sources" {
		t.Errorf("PeatCollection = %q, want data_sources", cfg.PeatCollection)
	}
	if cfg.PeatTLS {
		t.Error("PeatTLS should default to false")
	}
}

func TestLoadOverrides(t *testing.T) {
	clearAll(t)
	setRequired(t)
	t.Setenv("LISTEN_ADDR", ":9999")
	t.Setenv("OIDC_REDIRECT_URL", "https://app.example.com/auth/callback")
	t.Setenv("OIDC_POST_LOGOUT_REDIRECT_URL", "https://app.example.com/bye")
	t.Setenv("OIDC_SCOPES", "openid roles")
	t.Setenv("COOKIE_SECURE", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.RedirectURL != "https://app.example.com/auth/callback" {
		t.Errorf("RedirectURL = %q", cfg.RedirectURL)
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should be true")
	}
	if strings.Join(cfg.Scopes, " ") != "openid roles" {
		t.Errorf("Scopes = %v", cfg.Scopes)
	}
}

func TestLoadEmptyScopesFallsBackToOpenID(t *testing.T) {
	clearAll(t)
	setRequired(t)
	t.Setenv("OIDC_SCOPES", "   ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Scopes) != 1 || cfg.Scopes[0] != "openid" {
		t.Errorf("Scopes = %v, want [openid]", cfg.Scopes)
	}
}
