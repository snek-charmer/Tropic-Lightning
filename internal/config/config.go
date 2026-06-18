package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration, populated from environment variables.
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":3000".
	ListenAddr string

	// Issuer is the Keycloak realm issuer URL, e.g.
	// http://localhost:8080/realms/myrealm
	Issuer string

	// ClientID / ClientSecret identify this application as a Keycloak client.
	ClientID     string
	ClientSecret string

	// RedirectURL is the OIDC callback URL registered in Keycloak, e.g.
	// http://localhost:3000/auth/callback
	RedirectURL string

	// PostLogoutRedirectURL is where Keycloak sends the browser after logout.
	PostLogoutRedirectURL string

	// Scopes requested during the authorization code flow. "openid" is required;
	// "roles" makes Keycloak include realm/client roles in the tokens.
	Scopes []string

	// CookieSecure controls the Secure flag on the session cookie. Disable only
	// for local HTTP development.
	CookieSecure bool

	// AdminGroup is a Keycloak group whose members are treated as admins (in
	// addition to anyone holding the "admin" realm role). Matches the token's
	// "groups" claim. Defaults to the UDS Core admin group.
	AdminGroup string

	// PeatNodeAddr is the gRPC target of the local peat sidecar node that backs
	// data-source storage, e.g. "localhost:50051" or
	// "peat-node-peat-node.peat-system.svc:50051". peat owns persistence,
	// disconnected operation, and CRDT mesh sync.
	PeatNodeAddr string

	// PeatCollection is the peat document collection used for data sources.
	PeatCollection string

	// PeatTLS dials the peat node over TLS. Defaults false for the co-located
	// sidecar pattern (in-pod / localhost plaintext).
	PeatTLS bool
}

// Load reads configuration from the environment and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:            envOr("LISTEN_ADDR", ":3000"),
		Issuer:                os.Getenv("KEYCLOAK_ISSUER"),
		ClientID:              os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret:          os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:           envOr("OIDC_REDIRECT_URL", "http://localhost:3000/auth/callback"),
		PostLogoutRedirectURL: envOr("OIDC_POST_LOGOUT_REDIRECT_URL", "http://localhost:3000/"),
		Scopes:                splitScopes(envOr("OIDC_SCOPES", "openid profile email roles")),
		CookieSecure:          envOr("COOKIE_SECURE", "false") == "true",
		AdminGroup:            envOr("ADMIN_GROUP", "/UDS Core/Admin"),
		PeatNodeAddr:          os.Getenv("PEAT_NODE_ADDR"),
		PeatCollection:        envOr("PEAT_COLLECTION", "data_sources"),
		PeatTLS:               envOr("PEAT_TLS", "false") == "true",
	}

	var missing []string
	if cfg.Issuer == "" {
		missing = append(missing, "KEYCLOAK_ISSUER")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "OIDC_CLIENT_ID")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "OIDC_CLIENT_SECRET")
	}
	if cfg.PeatNodeAddr == "" {
		missing = append(missing, "PEAT_NODE_ADDR")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitScopes(s string) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []string{"openid"}
	}
	return fields
}
