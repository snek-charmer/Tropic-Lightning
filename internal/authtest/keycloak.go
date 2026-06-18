// Package authtest provides a fake Keycloak/OIDC provider for use in tests.
// It serves an OIDC discovery document, a JWKS endpoint, and a token endpoint,
// and can mint signed JWTs so the real token-verification path can be exercised
// without a live Keycloak instance.
package authtest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/config"
)

const (
	testKeyID    = "test-key"
	testClientID = "test-client"
	testSecret   = "test-secret"
	signingAlgRS = "RS256"
)

// Keycloak is a fake OIDC provider backed by an httptest.Server.
type Keycloak struct {
	Server *httptest.Server
	Issuer string

	// AccessClaims / IDClaims are returned (signed) by the token endpoint during
	// the authorization-code exchange. Tests may mutate these before driving a
	// callback to control nonce, audience, roles, etc.
	AccessClaims map[string]any
	IDClaims     map[string]any

	key    *rsa.PrivateKey
	signer jose.Signer
}

// NewKeycloak starts a fake provider and returns it. Caller should defer Close.
func NewKeycloak(t *testing.T) *Keycloak {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	k := &Keycloak{key: key, signer: signer}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", k.handleDiscovery)
	mux.HandleFunc("/jwks", k.handleJWKS)
	mux.HandleFunc("/token", k.handleToken)
	k.Server = httptest.NewServer(mux)
	k.Issuer = k.Server.URL

	// Sensible defaults a happy-path callback can use as-is.
	k.AccessClaims = map[string]any{
		"sub":                "user-123",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"realm_access":       map[string]any{"roles": []string{"user"}},
	}
	k.IDClaims = map[string]any{
		"sub":                "user-123",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"aud":                testClientID,
	}

	return k
}

// Close shuts down the underlying test server.
func (k *Keycloak) Close() { k.Server.Close() }

// Config returns a config pointed at this fake provider, using the test client.
func (k *Keycloak) Config() *config.Config {
	return &config.Config{
		ListenAddr:            ":0",
		Issuer:                k.Issuer,
		ClientID:              testClientID,
		ClientSecret:          testSecret,
		RedirectURL:           "http://localhost/auth/callback",
		PostLogoutRedirectURL: "http://localhost/",
		Scopes:                []string{"openid", "profile", "email", "roles"},
		CookieSecure:          false,
		AdminGroup:            "/UDS Core/Admin",
	}
}

// Authenticator builds a real *auth.Authenticator wired to this fake provider.
func (k *Keycloak) Authenticator(t *testing.T) *auth.Authenticator {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := auth.NewAuthenticator(ctx, k.Config())
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	return a
}

// SignToken mints a signed JWT from the given claims, filling in iss/iat/exp if
// the caller did not provide them.
func (k *Keycloak) SignToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	c := map[string]any{}
	for key, v := range claims {
		c[key] = v
	}
	if _, ok := c["iss"]; !ok {
		c["iss"] = k.Issuer
	}
	now := time.Now()
	if _, ok := c["iat"]; !ok {
		c["iat"] = now.Unix()
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = now.Add(time.Hour).Unix()
	}

	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	obj, err := k.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return s
}

func (k *Keycloak) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                k.Issuer,
		"authorization_endpoint":                k.Issuer + "/auth",
		"token_endpoint":                        k.Issuer + "/token",
		"jwks_uri":                              k.Issuer + "/jwks",
		"userinfo_endpoint":                     k.Issuer + "/userinfo",
		"end_session_endpoint":                  k.Issuer + "/logout",
		"id_token_signing_alg_values_supported": []string{signingAlgRS},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (k *Keycloak) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.key.Public(),
		KeyID:     testKeyID,
		Algorithm: signingAlgRS,
		Use:       "sig",
	}}}
	writeJSON(w, set)
}

func (k *Keycloak) handleToken(w http.ResponseWriter, r *http.Request) {
	// We don't validate the client credentials/code here — tests control the
	// claims that come back via AccessClaims/IDClaims.
	resp := map[string]any{
		"access_token": k.SignTokenForRequest(r, k.AccessClaims),
		"id_token":     k.SignTokenForRequest(r, k.IDClaims),
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	writeJSON(w, resp)
}

// SignTokenForRequest is like SignToken but usable from request handlers where
// there is no *testing.T. It panics on error (only reachable in test process).
func (k *Keycloak) SignTokenForRequest(_ *http.Request, claims map[string]any) string {
	c := map[string]any{"iss": k.Issuer}
	now := time.Now()
	c["iat"] = now.Unix()
	c["exp"] = now.Add(time.Hour).Unix()
	for key, v := range claims {
		c[key] = v
	}
	payload, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	obj, err := k.signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
