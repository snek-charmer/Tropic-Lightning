package auth

import (
	"context"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/config"
)

func TestInternalBackchannelEndpoints(t *testing.T) {
	cfg := &config.Config{
		Issuer:              "https://sso.uds.dev/realms/uds",
		ClientID:            "keycloak-portal",
		ClientSecret:        "x",
		RedirectURL:         "https://portal.uds.dev/auth/callback",
		Scopes:              []string{"openid"},
		KeycloakInternalURL: "http://keycloak-http.keycloak.svc.cluster.local:8080",
	}
	// No network: internal path skips discovery; NewRemoteKeySet is lazy.
	a, err := NewAuthenticator(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	// Front-channel (browser) auth URL must be the PUBLIC host.
	if got := a.oauth2.Endpoint.AuthURL; got != "https://sso.uds.dev/realms/uds/protocol/openid-connect/auth" {
		t.Errorf("auth URL = %q (want public)", got)
	}
	// Back-channel (pod) token URL must be the IN-CLUSTER host.
	want := "http://keycloak-http.keycloak.svc.cluster.local:8080/realms/uds/protocol/openid-connect/token"
	if got := a.oauth2.Endpoint.TokenURL; got != want {
		t.Errorf("token URL = %q, want %q", got, want)
	}
	// Logout stays public (browser).
	if got := a.LogoutURL(""); got == "" {
		t.Error("expected a logout URL")
	}
}
