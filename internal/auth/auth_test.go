package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/authtest"
)

// okHandler writes the verified username so tests can confirm the request
// reached the protected handler with claims attached.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(claims.PreferredUsername))
	})
}

func TestVerifyAccessToken(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	token := kc.SignToken(t, map[string]any{
		"sub":                "user-1",
		"preferred_username": "bob",
		"realm_access":       map[string]any{"roles": []string{"admin", "user"}},
		"resource_access": map[string]any{
			"test-client": map[string]any{"roles": []string{"editor"}},
		},
	})

	claims, err := authn.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.PreferredUsername != "bob" {
		t.Errorf("username = %q", claims.PreferredUsername)
	}
	if !claims.HasRealmRole("admin") {
		t.Error("expected admin realm role")
	}
	if !claims.HasClientRole("test-client", "editor") {
		t.Error("expected editor client role")
	}
}

func TestVerifyAccessTokenRejectsGarbage(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	if _, err := authn.VerifyAccessToken(context.Background(), "not-a-jwt"); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestAuthenticateValidBearer(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	token := kc.SignToken(t, map[string]any{"preferred_username": "carol"})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "carol" {
		t.Errorf("body = %q, want carol", rec.Body.String())
	}
}

func TestAuthenticateValidCookie(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	token := kc.SignToken(t, map[string]any{"preferred_username": "dave"})

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: token})
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "dave" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthenticateInvalidToken(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuthenticateMissingTokenJSON(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil) // no Accept: text/html
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want json", ct)
	}
}

func TestAuthenticateMissingTokenHTMLRedirects(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("location = %q, want /auth/login...", loc)
	} else if !strings.Contains(loc, "return_to=%2Fdashboard") {
		t.Errorf("location = %q, want return_to=/dashboard", loc)
	}
}

func TestRequireRealmRole(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	guard := authn.RequireRealmRole("admin")
	stack := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		authn.Authenticate(guard(okHandler())).ServeHTTP(rec, req)
		return rec
	}

	adminTok := kc.SignToken(t, map[string]any{
		"preferred_username": "root",
		"realm_access":       map[string]any{"roles": []string{"admin"}},
	})
	if rec := stack(adminTok); rec.Code != http.StatusOK {
		t.Errorf("admin: status = %d, want 200", rec.Code)
	}

	userTok := kc.SignToken(t, map[string]any{
		"preferred_username": "peon",
		"realm_access":       map[string]any{"roles": []string{"user"}},
	})
	if rec := stack(userTok); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}
}

func TestRequireClientRole(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	guard := authn.RequireClientRole("test-client", "editor")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	editorTok := kc.SignToken(t, map[string]any{
		"resource_access": map[string]any{
			"test-client": map[string]any{"roles": []string{"editor"}},
		},
	})
	req.Header.Set("Authorization", "Bearer "+editorTok)
	rec := httptest.NewRecorder()
	authn.Authenticate(guard(okHandler())).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("editor: status = %d, want 200", rec.Code)
	}
}

func TestAuthCodeURL(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	raw := authn.AuthCodeURL("state-xyz", "nonce-abc")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("state") != "state-xyz" {
		t.Errorf("state = %q", q.Get("state"))
	}
	if q.Get("nonce") != "nonce-abc" {
		t.Errorf("nonce = %q", q.Get("nonce"))
	}
	if q.Get("client_id") != "test-client" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
}

func TestLogoutURL(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	raw := authn.LogoutURL("id-token-hint")
	if !strings.HasPrefix(raw, kc.Issuer+"/logout") {
		t.Fatalf("logout URL = %q, want prefix %q/logout", raw, kc.Issuer)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("id_token_hint") != "id-token-hint" {
		t.Errorf("id_token_hint = %q", q.Get("id_token_hint"))
	}
	if q.Get("post_logout_redirect_uri") != "http://localhost/" {
		t.Errorf("post_logout_redirect_uri = %q", q.Get("post_logout_redirect_uri"))
	}
}

func TestRequireAdminViaGroup(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	guard := authn.RequireAdmin()
	call := func(claims map[string]any) int {
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.Header.Set("Authorization", "Bearer "+kc.SignToken(t, claims))
		rec := httptest.NewRecorder()
		authn.Authenticate(guard(okHandler())).ServeHTTP(rec, req)
		return rec.Code
	}

	// Admin via group only (no realm role).
	if code := call(map[string]any{"preferred_username": "g", "groups": []string{"/UDS Core/Admin"}}); code != http.StatusOK {
		t.Errorf("group admin: status = %d, want 200", code)
	}
	// Admin via realm role only.
	if code := call(map[string]any{"preferred_username": "r", "realm_access": map[string]any{"roles": []string{"admin"}}}); code != http.StatusOK {
		t.Errorf("role admin: status = %d, want 200", code)
	}
	// Neither -> forbidden.
	if code := call(map[string]any{"preferred_username": "n", "groups": []string{"/UDS Core/Viewer"}}); code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", code)
	}
}

func TestAuthenticateSilentRefresh(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	// An access token that is already expired (verification will fail).
	expired := kc.SignToken(t, map[string]any{
		"preferred_username": "s1",
		"exp":                time.Now().Add(-time.Minute).Unix(),
	})
	// The fake token endpoint returns a fresh, valid access token on refresh.
	kc.AccessClaims["preferred_username"] = "s1"

	req := httptest.NewRequest(http.MethodGet, "/missions", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: expired})
	req.AddCookie(&http.Cookie{Name: auth.RefreshTokenCookie, Value: "a-refresh-token"})
	rec := httptest.NewRecorder()

	authn.Authenticate(okHandler()).ServeHTTP(rec, req)

	// Request proceeds (no bounce to login) because the session was refreshed.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (expected silent refresh)", rec.Code)
	}
	if rec.Body.String() != "s1" {
		t.Errorf("body = %q, want s1", rec.Body.String())
	}
	// A fresh access-token cookie was written.
	var refreshed bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.AccessTokenCookie && c.Value != "" && c.Value != expired {
			refreshed = true
		}
	}
	if !refreshed {
		t.Error("expected a new access_token cookie after refresh")
	}
}

func TestAuthenticateNoRefreshTokenDenies(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	authn := kc.Authenticator(t)

	expired := kc.SignToken(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil) // no refresh cookie
	req.Header.Set("Authorization", "Bearer "+expired)
	rec := httptest.NewRecorder()
	authn.Authenticate(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no refresh token)", rec.Code)
	}
}
