package web_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/authtest"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/pilots"
	"github.com/defenseunicorns/keycloak-portal/internal/web"
)

// newServer wires a web.Server against the fake Keycloak and returns the router.
func newServer(t *testing.T, kc *authtest.Keycloak) http.Handler {
	t.Helper()
	ds := datasource.NewService(datasource.NewMemoryStore())
	pl := pilots.NewService(pilots.NewMemoryStore(), ds, nil)
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds, pl)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv.Routes()
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHomeUnauthenticated(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/auth/login") {
		t.Error("home page should show a login link when unauthenticated")
	}
}

func TestHomeAuthenticated(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	token := kc.SignToken(t, map[string]any{"preferred_username": "alice"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "/dashboard") {
		t.Error("home page should link to dashboard when authenticated")
	}
}

func TestLoginRedirectsAndSetsCookies(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	resp := rec.Result()
	if findCookie(resp, "oidc_state") == nil {
		t.Error("missing oidc_state cookie")
	}
	if findCookie(resp, "oidc_nonce") == nil {
		t.Error("missing oidc_nonce cookie")
	}

	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") == "" || loc.Query().Get("nonce") == "" {
		t.Error("authorization redirect should carry state and nonce")
	}
}

func TestCallbackHappyPath(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	// The fake token endpoint returns an ID token with this nonce; match it.
	kc.IDClaims["nonce"] = "n-123"
	kc.AccessClaims["preferred_username"] = "alice"

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=s-123", nil)
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s-123"})
	req.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "n-123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("location = %q, want /dashboard", loc)
	}
	if findCookie(rec.Result(), auth.AccessTokenCookie) == nil {
		t.Error("callback should set the access_token cookie")
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=wrong", nil)
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "right"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackRejectsBadNonce(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	kc.IDClaims["nonce"] = "server-nonce"

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=s", nil)
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: "s"})
	req.AddCookie(&http.Cookie{Name: "oidc_nonce", Value: "client-nonce-mismatch"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackPropagatesProviderError(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestLogoutClearsCookiesAndRedirects(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: "tok"})
	req.AddCookie(&http.Cookie{Name: "id_token", Value: "idtok"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), kc.Issuer+"/logout") {
		t.Errorf("location = %q, want keycloak logout", rec.Header().Get("Location"))
	}
	c := findCookie(rec.Result(), auth.AccessTokenCookie)
	if c == nil || c.MaxAge >= 0 {
		t.Error("access_token cookie should be cleared (MaxAge < 0)")
	}
}

func TestDashboardRendersRoles(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	token := kc.SignToken(t, map[string]any{
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []string{"admin", "auditor"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"alice", "admin", "auditor"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard should contain %q", want)
		}
	}
}

func TestAPIMeReturnsClaims(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	token := kc.SignToken(t, map[string]any{
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"realm_access":       map[string]any{"roles": []string{"user"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got auth.Claims
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.PreferredUsername != "alice" {
		t.Errorf("username = %q", got.PreferredUsername)
	}
	if !got.HasRealmRole("user") {
		t.Error("expected user realm role in /api/me")
	}
}

func TestAPIAdminRequiresAdminRole(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	call := func(roles []string) int {
		token := kc.SignToken(t, map[string]any{
			"preferred_username": "u",
			"realm_access":       map[string]any{"roles": roles},
		})
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call([]string{"admin"}); code != http.StatusOK {
		t.Errorf("admin role: status = %d, want 200", code)
	}
	if code := call([]string{"user"}); code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", code)
	}
}

func adminToken(t *testing.T, kc *authtest.Keycloak) string {
	return kc.SignToken(t, map[string]any{
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []string{"admin"}},
	})
}

func TestDataSourcesPageRequiresAdmin(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	userTok := kc.SignToken(t, map[string]any{
		"preferred_username": "bob",
		"realm_access":       map[string]any{"roles": []string{"user"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/datasources", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin /datasources status = %d, want 403", rec.Code)
	}
}

func TestDataSourceCreateAndListJSON(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	// Create via JSON API.
	body := `{"name":"telemetry","type":"postgres","endpoint":"postgres://h:5432/db","enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/datasources", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	var created datasource.DataSource
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.ID == "" {
		t.Errorf("created = %+v (expected generated ID)", created)
	}

	// List should contain it.
	lreq := httptest.NewRequest(http.MethodGet, "/api/datasources", nil)
	lreq.Header.Set("Authorization", "Bearer "+tok)
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list status = %d", lrec.Code)
	}
	var list []datasource.DataSource
	if err := json.Unmarshal(lrec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "telemetry" {
		t.Errorf("list = %+v", list)
	}
}

func TestDataSourceJSONFieldsRoundTrip(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	body := `{"name":"db","type":"postgres","endpoint":"postgres://h/db","secret_ref":"k8s/db","enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/datasources", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	var created datasource.DataSource
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.SecretRef != "k8s/db" {
		t.Errorf("secret_ref = %q, want k8s/db (snake_case JSON must bind)", created.SecretRef)
	}
}

func TestDataSourceCreateValidationJSON(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	req := httptest.NewRequest(http.MethodPost, "/api/datasources", strings.NewReader(`{"name":"","type":"bogus"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestDataSourceDeleteJSON(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	// Create one.
	req := httptest.NewRequest(http.MethodPost, "/api/datasources",
		strings.NewReader(`{"name":"x","type":"http","endpoint":"http://e"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var created datasource.DataSource
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// Delete it.
	dreq := httptest.NewRequest(http.MethodDelete, "/api/datasources/"+created.ID, nil)
	dreq.Header.Set("Authorization", "Bearer "+tok)
	drec := httptest.NewRecorder()
	h.ServeHTTP(drec, dreq)
	if drec.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", drec.Code)
	}

	// Deleting again -> 404.
	drec2 := httptest.NewRecorder()
	h.ServeHTTP(drec2, dreq)
	if drec2.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", drec2.Code)
	}
}

func TestDataSourceCreateViaFormRedirects(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	form := url.Values{"name": {"feed"}, "type": {"http"}, "endpoint": {"http://feed"}, "enabled": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/datasources", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form create status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=created") {
		t.Errorf("redirect location = %q, want ok=created", loc)
	}
}

func TestPeatStatusEndpoint(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	// Any authenticated user can read peat status. The in-memory store reports a
	// reachable (connected) status with no error.
	token := kc.SignToken(t, map[string]any{"preferred_username": "alice"})
	req := httptest.NewRequest(http.MethodGet, "/api/peat/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["connected"] != true {
		t.Errorf("connected = %v, want true", got["connected"])
	}
}

func TestPeatStatusRequiresAuth(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	req := httptest.NewRequest(http.MethodGet, "/api/peat/status", nil) // no token
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestDataSourcesAccessibleViaAdminGroup(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	// User has the admin GROUP but no admin realm role.
	token := kc.SignToken(t, map[string]any{
		"preferred_username": "alice",
		"groups":             []string{"/UDS Core/Admin"},
	})
	req := httptest.NewRequest(http.MethodGet, "/datasources", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("group-admin /datasources status = %d, want 200", rec.Code)
	}
}

func TestPilotsRequireAdmin(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	userTok := kc.SignToken(t, map[string]any{
		"preferred_username": "bob",
		"realm_access":       map[string]any{"roles": []string{"user"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/pilots", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin /pilots = %d, want 403", rec.Code)
	}
}

func TestPilotsImportAndList(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	// Import (form POST) -> redirect with imported count.
	ireq := httptest.NewRequest(http.MethodPost, "/pilots/import", nil)
	ireq.Header.Set("Authorization", "Bearer "+tok)
	irec := httptest.NewRecorder()
	h.ServeHTTP(irec, ireq)
	if irec.Code != http.StatusSeeOther {
		t.Fatalf("import status = %d, want 303", irec.Code)
	}
	if loc := irec.Header().Get("Location"); !strings.Contains(loc, "imported=") {
		t.Errorf("redirect = %q, want imported=", loc)
	}

	// JSON list now returns pilots.
	lreq := httptest.NewRequest(http.MethodGet, "/api/pilots", nil)
	lreq.Header.Set("Authorization", "Bearer "+tok)
	lrec := httptest.NewRecorder()
	h.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list status = %d", lrec.Code)
	}
	var list []pilots.Pilot
	if err := json.Unmarshal(lrec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) < 100 {
		t.Errorf("listed %d pilots, want many", len(list))
	}
}
