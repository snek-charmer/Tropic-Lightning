package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/authtest"
	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/operators"
	"github.com/defenseunicorns/keycloak-portal/internal/pilots"
	"github.com/defenseunicorns/keycloak-portal/internal/web"
)

// newServer wires a web.Server against the fake Keycloak and returns the router.
func newServer(t *testing.T, kc *authtest.Keycloak) http.Handler {
	t.Helper()
	ds := datasource.NewService(datasource.NewMemoryStore())
	pl := pilots.NewService(pilots.NewMemoryStore(), ds, nil)
	dsets := dataset.NewService(dataset.NewMemoryStore(), ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds, pl, dsets, ops)
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

// opServer builds a server with explicit pilots + operators services so tests
// can pre-seed pilots and control assignments.
func opServer(t *testing.T, kc *authtest.Keycloak, pstore *pilots.MemoryStore, ops *operators.Service) http.Handler {
	t.Helper()
	ds := datasource.NewService(datasource.NewMemoryStore())
	pl := pilots.NewService(pstore, ds, nil)
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds, pl, dataset.NewService(dataset.NewMemoryStore(), ds, nil), ops)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return srv.Routes()
}

func TestMissionsRequiresAssignment(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "pilots", "USAF Pilots", operators.KindPilots, "pilots")
	h := opServer(t, kc, pilots.NewMemoryStore(), ops)

	tok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	do := func() int {
		req := httptest.NewRequest(http.MethodGet, "/missions", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// Unassigned operator is denied.
	if code := do(); code != http.StatusForbidden {
		t.Errorf("unassigned /missions = %d, want 403", code)
	}
	// After assignment, allowed.
	_ = ops.SetAssignments(ctx, "pilots", []string{"s1"})
	if code := do(); code != http.StatusOK {
		t.Errorf("assigned /missions = %d, want 200", code)
	}
}

func TestOperatorCanEditPilotStatus(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	pstore := pilots.NewMemoryStore()
	_ = pstore.Put(ctx, pilots.Pilot{PilotID: "P0001", MissionStatus: pilots.StatusAvailable})
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "pilots", "USAF Pilots", operators.KindPilots, "pilots")
	_ = ops.SetAssignments(ctx, "pilots", []string{"s1"})
	h := opServer(t, kc, pstore, ops)

	tok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	form := url.Values{"status": {"grounded"}, "note": {"sick"}}
	req := httptest.NewRequest(http.MethodPost, "/pilots/P0001/status", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status edit = %d, want 303", rec.Code)
	}
	got, _ := pstore.Get(ctx, "P0001")
	if got.Available() || got.StatusBy != "s1" || got.StatusNote != "sick" {
		t.Errorf("pilot after edit = %+v", got)
	}
}

func TestDashboardAdminViewSelector(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)

	adminTok := kc.SignToken(t, map[string]any{
		"preferred_username": "alice",
		"groups":             []string{"/UDS Core/Admin"},
	})
	get := func(q string) string {
		req := httptest.NewRequest(http.MethodGet, "/dashboard"+q, nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: adminTok})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	// Admin default view shows the admin card + selector.
	body := get("")
	if !strings.Contains(body, "View as") || !strings.Contains(body, "/datasources") {
		t.Error("admin dashboard should show the view selector and admin card")
	}
	// Operator preview shows the "Your datasets" card, not the admin card.
	op := get("?view=operator")
	if !strings.Contains(op, "Your datasets") {
		t.Error("operator view should show the 'Your datasets' card")
	}
	if strings.Contains(op, "/datasources") {
		t.Error("operator view should NOT show admin data-source link")
	}

	// Non-admin never sees the selector; gets the operator dashboard.
	userTok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: userTok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "View as") {
		t.Error("non-admin should not see the view selector")
	}
	if !strings.Contains(rec.Body.String(), "Your datasets") {
		t.Error("non-admin dashboard should show the operator 'Your datasets' card")
	}
}

func TestMissionsFilterByBase(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	pstore := pilots.NewMemoryStore()
	ctx := context.Background()
	_ = pstore.Put(ctx, pilots.Pilot{PilotID: "P1", Base: "Hill AFB", Aircraft: "F-16", MissionStatus: pilots.StatusAvailable})
	_ = pstore.Put(ctx, pilots.Pilot{PilotID: "P2", Base: "Nellis AFB", Aircraft: "F-16", MissionStatus: pilots.StatusAvailable})
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "pilots", "USAF Pilots", operators.KindPilots, "pilots")
	_ = ops.SetAssignments(ctx, "pilots", []string{"s1"})
	h := opServer(t, kc, pstore, ops)
	tok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})

	req := httptest.NewRequest(http.MethodGet, "/missions?base=Hill+AFB", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "P1") {
		t.Error("Hill AFB pilot P1 should be listed")
	}
	if strings.Contains(body, ">P2<") || strings.Contains(body, "/pilots/P2/status") {
		t.Error("Nellis pilot P2 should be filtered out")
	}
}

func TestUploadParseAndImportFlow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	// 1) Upload a CSV (multipart) -> JSON preview with a hold token.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "roster.csv")
	_, _ = fw.Write([]byte("name,age,ssn\nAlice,30,111\nBob,41,222\n"))
	_ = mw.Close()

	up := httptest.NewRequest(http.MethodPost, "/datasources/upload", &buf)
	up.Header.Set("Authorization", "Bearer "+tok)
	up.Header.Set("Content-Type", mw.FormDataContentType())
	uprec := httptest.NewRecorder()
	h.ServeHTTP(uprec, up)
	if uprec.Code != http.StatusOK {
		t.Fatalf("upload status = %d (body %s)", uprec.Code, uprec.Body.String())
	}
	var prev struct {
		Token   string   `json:"token"`
		Columns []string `json:"columns"`
		Total   int      `json:"total"`
	}
	if err := json.Unmarshal(uprec.Body.Bytes(), &prev); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if prev.Token == "" || len(prev.Columns) != 3 || prev.Total != 2 {
		t.Fatalf("preview = %+v", prev)
	}

	// 2) Import keeping name+age (drop ssn).
	form := url.Values{"token": {prev.Token}, "name": {"Roster"}, "col": {"name", "age"}}
	imp := httptest.NewRequest(http.MethodPost, "/datasources/import", strings.NewReader(form.Encode()))
	imp.Header.Set("Authorization", "Bearer "+tok)
	imp.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	imprec := httptest.NewRecorder()
	h.ServeHTTP(imprec, imp)
	if imprec.Code != http.StatusSeeOther {
		t.Fatalf("import status = %d", imprec.Code)
	}
	loc := imprec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/datasets/") {
		t.Fatalf("redirect = %q", loc)
	}

	// 3) View the dataset -> shows kept columns, not ssn.
	vrec := httptest.NewRecorder()
	vreq := httptest.NewRequest(http.MethodGet, loc, nil)
	vreq.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(vrec, vreq)
	if vrec.Code != http.StatusOK {
		t.Fatalf("view status = %d", vrec.Code)
	}
	body := vrec.Body.String()
	if !strings.Contains(body, "Alice") || strings.Contains(body, "ssn") {
		t.Errorf("view should show kept data without ssn column")
	}
}

func TestUploadRequiresAdmin(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	userTok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := httptest.NewRequest(http.MethodGet, "/datasources/upload", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin upload page = %d, want 403", rec.Code)
	}
}

func TestAdminPreviewSpecificOperator(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ops := operators.NewService(operators.NewMemoryStore())
	_, _ = ops.CreateOperator(ctx, "s4", "Op Four")
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_ = ops.SetAssignments(ctx, "ds_roster", []string{"s4"})
	h := opServer(t, kc, pilots.NewMemoryStore(), ops)

	adminTok := kc.SignToken(t, map[string]any{"preferred_username": "alice", "groups": []string{"/UDS Core/Admin"}})
	req := httptest.NewRequest(http.MethodGet, "/dashboard?view=operator&as=s4", nil)
	req.AddCookie(&http.Cookie{Name: auth.AccessTokenCookie, Value: adminTok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/datasets/ds_roster") {
		t.Error("previewing s4 should show their assigned dataset link")
	}
	if !strings.Contains(body, "s4") {
		t.Error("preview should indicate operator s4")
	}
}

func TestOperatorsPageReconcilesUploadedDatasets(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	// A dataset imported before the assignment registry existed: only a catalog entry.
	_, _ = ds.Create(ctx, datasource.Input{Name: "Roster", Type: "file", Endpoint: "dataset://ds_roster", Enabled: true})
	ops := operators.NewService(operators.NewMemoryStore())
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		pilots.NewService(pilots.NewMemoryStore(), ds, nil),
		dataset.NewService(dataset.NewMemoryStore(), ds, nil), ops)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()

	adminTok := kc.SignToken(t, map[string]any{"preferred_username": "alice", "groups": []string{"/UDS Core/Admin"}})
	req := httptest.NewRequest(http.MethodGet, "/operators", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/datasets/ds_roster/assign") {
		t.Error("operators page should list the uploaded dataset as assignable after reconcile")
	}
}
