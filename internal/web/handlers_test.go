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
	"github.com/defenseunicorns/keycloak-portal/internal/combine"
	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/deck"
	"github.com/defenseunicorns/keycloak-portal/internal/httpsource"
	"github.com/defenseunicorns/keycloak-portal/internal/operators"
	"github.com/defenseunicorns/keycloak-portal/internal/views"
	"github.com/defenseunicorns/keycloak-portal/internal/weather"
	"github.com/defenseunicorns/keycloak-portal/internal/web"
)

// newServer wires a web.Server against the fake Keycloak and returns the router.
func newServer(t *testing.T, kc *authtest.Keycloak) http.Handler {
	t.Helper()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dsets := dataset.NewService(dataset.NewMemoryStore(), ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsets, ops, nil, nil, nil, nil, nil)
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
	// Admin default view shows the admin cards + selector. ("Data sources →" is
	// the admin content card; the bare nav link is present on every admin page.)
	body := get("")
	if !strings.Contains(body, "Viewing as") || !strings.Contains(body, "Data sources →") {
		t.Error("admin dashboard should show the view selector and admin card")
	}
	// Operator preview shows the "Your data sources" card, not the admin cards.
	op := get("?view=operator")
	if !strings.Contains(op, "Your data sources") {
		t.Error("operator view should show the 'Your data sources' card")
	}
	if strings.Contains(op, "Data sources →") {
		t.Error("operator view should NOT show the admin data-source card")
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
	if !strings.Contains(rec.Body.String(), "Your data sources") {
		t.Error("non-admin dashboard should show the operator 'Your data sources' card")
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

func TestCatalogReconcilesUploadedDatasets(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	// A dataset present only as a catalog entry (dataset:// endpoint).
	_, _ = ds.Create(ctx, datasource.Input{Name: "Roster", Type: "file", Endpoint: "dataset://ds_roster", Enabled: true})
	ops := operators.NewService(operators.NewMemoryStore())
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dataset.NewService(dataset.NewMemoryStore(), ds, nil), ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()

	// Any authenticated user sees it in the catalog with a subscribe control.
	tok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := httptest.NewRequest(http.MethodGet, "/catalog", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/catalog/ds_roster/subscribe") || !strings.Contains(body, "Roster") {
		t.Error("catalog should list the uploaded dataset with a subscribe control after reconcile")
	}
}

func TestSelfSubscribeGrantsAccess(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name"})
	_ = dstore.PutRow(ctx, "ds_roster", "r1", map[string]string{"name": "Alice"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	srv, _ := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, nil, nil)
	h := srv.Routes()
	tok := kc.SignToken(t, map[string]any{"preferred_username": "s1", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := func(method, target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// Before subscribing: no access to the data.
	if rec := req(http.MethodGet, "/datasets/ds_roster"); rec.Code != http.StatusForbidden {
		t.Fatalf("pre-subscribe view = %d, want 403", rec.Code)
	}
	// Self-subscribe.
	if rec := req(http.MethodPost, "/catalog/ds_roster/subscribe"); rec.Code != http.StatusSeeOther {
		t.Fatalf("subscribe = %d", rec.Code)
	}
	if !ops.IsAssigned(ctx, "ds_roster", "s1") {
		t.Fatal("s1 should be subscribed after subscribing")
	}
	// Now access is granted, and it appears on the dashboard.
	if rec := req(http.MethodGet, "/datasets/ds_roster"); rec.Code != http.StatusOK {
		t.Errorf("post-subscribe view = %d, want 200", rec.Code)
	}
	if rec := req(http.MethodGet, "/dashboard"); !strings.Contains(rec.Body.String(), "Roster") {
		t.Error("subscribed dataset should appear on the dashboard")
	}
	// Unsubscribe revokes access again.
	if rec := req(http.MethodPost, "/catalog/ds_roster/unsubscribe"); rec.Code != http.StatusSeeOther {
		t.Fatalf("unsubscribe = %d", rec.Code)
	}
	if rec := req(http.MethodGet, "/datasets/ds_roster"); rec.Code != http.StatusForbidden {
		t.Errorf("post-unsubscribe view = %d, want 403", rec.Code)
	}
}

func TestOperatorCanEditAssignedDataset(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name"})
	_ = dstore.PutRow(ctx, "ds_roster", "r000001", map[string]string{"name": "Alice"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_ = ops.SetAssignments(ctx, "ds_roster", []string{"s4"})

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := kc.SignToken(t, map[string]any{"preferred_username": "s4", "realm_access": map[string]any{"roles": []string{"user"}}})

	post := func(path string, form url.Values) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Add column + row as the assigned operator.
	if code := post("/datasets/ds_roster/columns/add", url.Values{"name": {"base"}}); code != http.StatusSeeOther {
		t.Fatalf("add column = %d", code)
	}
	if code := post("/datasets/ds_roster/rows/add", url.Values{"f_name": {"Bob"}, "f_base": {"Nellis"}}); code != http.StatusSeeOther {
		t.Fatalf("add row = %d", code)
	}
	_, cols, rows, _ := dsvc.View(ctx, "ds_roster")
	if len(cols) != 2 || len(rows) != 2 {
		t.Fatalf("after edits: cols=%v rows=%d", cols, len(rows))
	}

	// An UNassigned operator cannot edit.
	tok2 := kc.SignToken(t, map[string]any{"preferred_username": "nobody", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := httptest.NewRequest(http.MethodPost, "/datasets/ds_roster/columns/add", strings.NewReader("name=x"))
	req.Header.Set("Authorization", "Bearer "+tok2)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("unassigned edit = %d, want 403", rec.Code)
	}
}

func TestOperatorUpdatesExistingRow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_roster", "r000001", map[string]string{"name": "Alice", "status": ""})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_ = ops.SetAssignments(ctx, "ds_roster", []string{"s4"})
	srv, _ := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, nil, nil)
	h := srv.Routes()

	tok := kc.SignToken(t, map[string]any{"preferred_username": "s4", "realm_access": map[string]any{"roles": []string{"user"}}})
	form := url.Values{"id": {"r000001"}, "f_name": {"Alice"}, "f_status": {"grounded"}}
	req := httptest.NewRequest(http.MethodPost, "/datasets/ds_roster/rows/update?edit=1", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update = %d", rec.Code)
	}
	// Redirect preserves edit mode.
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "edit=1") {
		t.Errorf("redirect %q should preserve edit mode", loc)
	}
	got, _ := dstore.ListRows(ctx, "ds_roster")
	if got[0].Fields["status"] != "grounded" {
		t.Errorf("row not updated: %+v", got[0].Fields)
	}
}

func TestOperatorBulkSave(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_roster", "r000001", map[string]string{"name": "Alice", "status": ""})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_ = ops.SetAssignments(ctx, "ds_roster", []string{"s4"})
	srv, _ := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, nil, nil)
	h := srv.Routes()

	body := `{"rows":[{"id":"r000001","fields":{"name":"Alice","status":"grounded"}},{"id":"","fields":{"name":"Bob","status":"ok"}}],"deletes":[]}`
	tok := kc.SignToken(t, map[string]any{"preferred_username": "s4", "realm_access": map[string]any{"roles": []string{"user"}}})
	req := httptest.NewRequest(http.MethodPost, "/datasets/ds_roster/bulk", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk = %d (%s)", rec.Code, rec.Body.String())
	}
	got, _ := dstore.ListRows(ctx, "ds_roster")
	if len(got) != 2 {
		t.Fatalf("rows = %d, want 2", len(got))
	}

	// Unassigned user -> 403.
	tok2 := kc.SignToken(t, map[string]any{"preferred_username": "nobody", "realm_access": map[string]any{"roles": []string{"user"}}})
	req2 := httptest.NewRequest(http.MethodPost, "/datasets/ds_roster/bulk", strings.NewReader(`{"rows":[]}`))
	req2.Header.Set("Authorization", "Bearer "+tok2)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("unassigned bulk = %d, want 403", rec2.Code)
	}
}

func TestUploadDelimiterReparse(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	h := newServer(t, kc)
	tok := adminToken(t, kc)

	// Upload a pipe-delimited CSV.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "piped.csv")
	_, _ = fw.Write([]byte("a|b|c\n1|2|3\n"))
	_ = mw.Close()
	up := httptest.NewRequest(http.MethodPost, "/datasources/upload", &buf)
	up.Header.Set("Authorization", "Bearer "+tok)
	up.Header.Set("Content-Type", mw.FormDataContentType())
	uprec := httptest.NewRecorder()
	h.ServeHTTP(uprec, up)
	if uprec.Code != http.StatusOK {
		t.Fatalf("upload = %d", uprec.Code)
	}
	var prev struct {
		Token     string   `json:"token"`
		Columns   []string `json:"columns"`
		Delimiter string   `json:"delimiter"`
	}
	_ = json.Unmarshal(uprec.Body.Bytes(), &prev)
	if prev.Delimiter != "pipe" || len(prev.Columns) != 3 {
		t.Fatalf("auto-detect: delim=%q cols=%d", prev.Delimiter, len(prev.Columns))
	}

	// Re-preview forcing comma -> 1 column.
	form := url.Values{"token": {prev.Token}, "delimiter": {"comma"}}
	pr := httptest.NewRequest(http.MethodPost, "/datasources/preview", strings.NewReader(form.Encode()))
	pr.Header.Set("Authorization", "Bearer "+tok)
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	prrec := httptest.NewRecorder()
	h.ServeHTTP(prrec, pr)
	var prev2 struct {
		Columns []string `json:"columns"`
	}
	_ = json.Unmarshal(prrec.Body.Bytes(), &prev2)
	if len(prev2.Columns) != 1 {
		t.Errorf("forced comma cols = %d, want 1", len(prev2.Columns))
	}
}

func TestDatasetStatusWheel(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_roster", "r1", map[string]string{"name": "A", "status": "ready"})
	_ = dstore.PutRow(ctx, "ds_roster", "r2", map[string]string{"name": "B", "status": "ready"})
	_ = dstore.PutRow(ctx, "ds_roster", "r3", map[string]string{"name": "C", "status": "down"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)

	// Set the visualization to a status wheel grouped by "status".
	form := url.Values{"type": {"wheel"}, "group_by": {"status"}}
	pr := httptest.NewRequest(http.MethodPost, "/datasets/ds_roster/view", strings.NewReader(form.Encode()))
	pr.Header.Set("Authorization", "Bearer "+tok)
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, pr)
	if prr.Code != http.StatusSeeOther {
		t.Fatalf("set view = %d", prr.Code)
	}

	// The viewer now renders the wheel: a conic-gradient and the legend counts.
	vr := httptest.NewRequest(http.MethodGet, "/datasets/ds_roster", nil)
	vr.Header.Set("Authorization", "Bearer "+tok)
	vrr := httptest.NewRecorder()
	h.ServeHTTP(vrr, vr)
	body := vrr.Body.String()
	if !strings.Contains(body, "conic-gradient") {
		t.Error("wheel view should render a conic-gradient donut")
	}
	if !strings.Contains(body, "Grouped by") || !strings.Contains(body, "ready") {
		t.Error("wheel legend should show the grouped values")
	}
}

func TestWeatherConnectorCreateFlow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"current":{"time":"2026-06-18T12:00","temperature_2m":18.0,"wind_speed_10m":9.0,"weather_code":0}}`))
	}))
	defer api.Close()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	wx := weather.NewService(weather.NewMemoryStore(), dstore, nil)
	wx.SetBaseURL(api.URL)

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, wx, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)

	form := url.Values{"name": {"AOR"}, "locations": {"Hill AFB, 41.124, -111.973\nRamstein, 49.437, 7.6"}}
	cr := httptest.NewRequest(http.MethodPost, "/datasources/weather", strings.NewReader(form.Encode()))
	cr.Header.Set("Authorization", "Bearer "+tok)
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, cr)
	if crr.Code != http.StatusSeeOther {
		t.Fatalf("create weather = %d (%s)", crr.Code, crr.Body.String())
	}
	if loc := crr.Header().Get("Location"); loc != "/datasets/wx_aor" {
		t.Fatalf("redirect = %q", loc)
	}

	// The dataset exists with the two locations' current conditions.
	rows, err := dstore.ListRows(ctx, "wx_aor")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %d, %v", len(rows), err)
	}
	// And it's assignable + viewable through the portal.
	vr := httptest.NewRequest(http.MethodGet, "/datasets/wx_aor", nil)
	vr.Header.Set("Authorization", "Bearer "+tok)
	vrr := httptest.NewRecorder()
	h.ServeHTTP(vrr, vr)
	if !strings.Contains(vrr.Body.String(), "Hill AFB") {
		t.Error("weather dataset view should list the configured location")
	}
}

func TestHTTPSourceCreateAndRefresh(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls == 0 {
			_, _ = w.Write([]byte(`{"data":[{"id":"1","name":"alpha"},{"id":"2","name":"bravo"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"data":[{"id":"1","name":"alpha-updated"}]}`))
		}
		calls++
	}))
	defer api.Close()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	hs := httpsource.NewService(httpsource.NewMemoryStore(), dstore, nil)

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, hs, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)

	form := url.Values{"name": {"Feed"}, "url": {api.URL}, "record_path": {"data"}, "auth_type": {"none"}}
	cr := httptest.NewRequest(http.MethodPost, "/datasources/http", strings.NewReader(form.Encode()))
	cr.Header.Set("Authorization", "Bearer "+tok)
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, cr)
	if crr.Code != http.StatusSeeOther || crr.Header().Get("Location") != "/datasets/api_feed" {
		t.Fatalf("create = %d -> %q (%s)", crr.Code, crr.Header().Get("Location"), crr.Body.String())
	}
	if rows, _ := dstore.ListRows(ctx, "api_feed"); len(rows) != 2 {
		t.Fatalf("rows after create = %d", len(rows))
	}

	// The view shows the live-source refresh control.
	vr := httptest.NewRequest(http.MethodGet, "/datasets/api_feed", nil)
	vr.Header.Set("Authorization", "Bearer "+tok)
	vrr := httptest.NewRecorder()
	h.ServeHTTP(vrr, vr)
	if !strings.Contains(vrr.Body.String(), "Refresh now") {
		t.Error("live dataset view should offer a Refresh now button")
	}

	// Refresh re-pulls: snapshot shrinks to one row.
	rr := httptest.NewRequest(http.MethodPost, "/datasets/api_feed/refresh", nil)
	rr.Header.Set("Authorization", "Bearer "+tok)
	rrr := httptest.NewRecorder()
	h.ServeHTTP(rrr, rr)
	if rrr.Code != http.StatusSeeOther {
		t.Fatalf("refresh = %d", rrr.Code)
	}
	rows, _ := dstore.ListRows(ctx, "api_feed")
	if len(rows) != 1 || rows[0].Fields["name"] != "alpha-updated" {
		t.Errorf("rows after refresh = %v", rows)
	}
}

func TestSavedViewsFlow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_x", "X", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_x", "r1", map[string]string{"name": "A", "status": "ready"})
	_ = dstore.PutRow(ctx, "ds_x", "r2", map[string]string{"name": "B", "status": "down"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	vw := views.NewService(views.NewMemoryStore())

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, vw, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)
	do := func(method, target string, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, target, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, target, nil)
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	// Save a default view filtering status=down.
	save := do(http.MethodPost, "/datasets/ds_x/views",
		url.Values{"name": {"Down"}, "col": {"status"}, "val": {"down"}, "default": {"on"}}.Encode())
	if save.Code != http.StatusSeeOther {
		t.Fatalf("save view = %d (%s)", save.Code, save.Body.String())
	}
	applied := save.Header().Get("Location")
	if !strings.Contains(applied, "view=") || !strings.Contains(applied, "val=down") {
		t.Fatalf("save redirect = %q", applied)
	}

	// Opening the dataset "clean" auto-applies the default (302 to the view).
	clean := do(http.MethodGet, "/datasets/ds_x", "")
	if clean.Code != http.StatusFound {
		t.Fatalf("clean open = %d, want 302 (default auto-apply)", clean.Code)
	}
	if loc := clean.Header().Get("Location"); !strings.Contains(loc, "val=down") {
		t.Errorf("default redirect = %q, want the saved filter", loc)
	}

	// Following the applied view shows only the matching row (B), not A, and lists
	// the saved view.
	view := do(http.MethodGet, applied, "")
	if view.Code != http.StatusOK {
		t.Fatalf("view open = %d", view.Code)
	}
	body := view.Body.String()
	if !strings.Contains(body, "Saved views") || !strings.Contains(body, ">★ Down<") && !strings.Contains(body, "Down") {
		t.Error("view should list the saved 'Down' view")
	}
	if !strings.Contains(body, ">B<") || strings.Contains(body, ">A<") {
		t.Errorf("applied view should show only status=down rows (B, not A)")
	}

	// "All rows" (view=none) bypasses the default and shows everything.
	all := do(http.MethodGet, "/datasets/ds_x?view=none", "")
	if all.Code != http.StatusOK || !strings.Contains(all.Body.String(), ">A<") {
		t.Errorf("view=none should show all rows incl. A (code %d)", all.Code)
	}

	// Delete the view; clean open no longer redirects.
	vid := mustViewID(t, applied)
	del := do(http.MethodPost, "/datasets/ds_x/views/"+vid+"/delete", "")
	if del.Code != http.StatusSeeOther {
		t.Fatalf("delete view = %d", del.Code)
	}
	if again := do(http.MethodGet, "/datasets/ds_x", ""); again.Code != http.StatusOK {
		t.Errorf("after delete, clean open = %d, want 200 (no default)", again.Code)
	}
}

func mustViewID(t *testing.T, applied string) string {
	t.Helper()
	u, err := url.Parse(applied)
	if err != nil {
		t.Fatalf("parse %q: %v", applied, err)
	}
	id := u.Query().Get("view")
	if id == "" {
		t.Fatalf("no view id in %q", applied)
	}
	return id
}

// TestSavedViewsSwitch guards against the querystring being percent-encoded into
// a single broken parameter (which made every saved-view chip load the same
// unfiltered data — you couldn't switch between views).
func TestSavedViewsSwitch(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_x", "X", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_x", "r1", map[string]string{"name": "A", "status": "ready"})
	_ = dstore.PutRow(ctx, "ds_x", "r2", map[string]string{"name": "B", "status": "down"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	vw := views.NewService(views.NewMemoryStore())
	down, _ := vw.Save(ctx, views.View{Owner: "alice", Collection: "ds_x", Name: "Down", FilterCol: "status", FilterVal: "down"})
	ready, _ := vw.Save(ctx, views.View{Owner: "alice", Collection: "ds_x", Name: "Ready", FilterCol: "status", FilterVal: "ready"})

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, vw, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)
	get := func(target string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// The chip hrefs must carry real query params, not percent-encoded ones.
	_, page := get("/datasets/ds_x?view=none")
	if strings.Contains(page, "col%3d") || strings.Contains(page, "%26val") {
		t.Fatal("saved-view links are percent-encoded into a single broken param")
	}

	// Applying each view returns its own filtered rows.
	applyQ := func(v views.View) string {
		return "/datasets/ds_x?col=" + v.FilterCol + "&val=" + v.FilterVal + "&view=" + v.ID
	}
	_, d := get(applyQ(down))
	if !strings.Contains(d, ">B<") || strings.Contains(d, ">A<") {
		t.Error("Down view should show only B")
	}
	_, r := get(applyQ(ready))
	if !strings.Contains(r, ">A<") || strings.Contains(r, ">B<") {
		t.Error("Ready view should show only A")
	}
}

func TestDatasetBarAndStats(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_r", "Roster", []string{"base", "hrs"})
	_ = dstore.PutRow(ctx, "ds_r", "r1", map[string]string{"base": "Hill", "hrs": "100"})
	_ = dstore.PutRow(ctx, "ds_r", "r2", map[string]string{"base": "Hill", "hrs": "50"})
	_ = dstore.PutRow(ctx, "ds_r", "r3", map[string]string{"base": "Ramstein", "hrs": "30"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_r", "Roster", operators.KindGeneric, "ds_r")

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)
	get := func(target string) string {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}

	// Bar chart: sum of hrs by base via per-view override params.
	bar := get("/datasets/ds_r?vtype=bar&vgroup=base&vval=hrs&vagg=sum&view=x")
	if !strings.Contains(bar, "sum of hrs by base") || !strings.Contains(bar, ">150<") || !strings.Contains(bar, ">30<") {
		t.Errorf("bar chart should show summed hrs per base")
	}
	// Summary stats over hrs.
	stats := get("/datasets/ds_r?vtype=stats&vval=hrs&view=x")
	if !strings.Contains(stats, "SUM") || !strings.Contains(stats, ">180<") {
		t.Errorf("stats should show SUM 180 (100+50+30)")
	}
	// Line chart renders an SVG.
	line := get("/datasets/ds_r?vtype=line&vgroup=hrs&vval=hrs&vagg=max&view=x")
	if !strings.Contains(line, "<polyline") {
		t.Errorf("line chart should render an SVG polyline")
	}
}

// TestVizSwitchApplies guards the bug where selecting a new visualization didn't
// change the display because a stale vtype override (carried in the form's
// action query) masked the new selection.
func TestVizSwitchApplies(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_r", "R", []string{"base"})
	_ = dstore.PutRow(ctx, "ds_r", "r1", map[string]string{"base": "Hill"})
	_ = dstore.PutRow(ctx, "ds_r", "r2", map[string]string{"base": "Hill"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_r", "R", operators.KindGeneric, "ds_r")
	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)

	// Select "bar" while the page already carried a wheel override.
	form := url.Values{"type": {"bar"}, "group_by": {"base"}, "agg": {"count"}}
	pr := httptest.NewRequest(http.MethodPost, "/datasets/ds_r/view?vtype=wheel&vgroup=base", strings.NewReader(form.Encode()))
	pr.Header.Set("Authorization", "Bearer "+tok)
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, pr)
	loc := prr.Header().Get("Location")
	if !strings.Contains(loc, "vtype=bar") || strings.Contains(loc, "vtype=wheel") {
		t.Fatalf("redirect should apply the new viz (bar), got %q", loc)
	}
	// Following it renders the bar chart, not the wheel.
	gr := httptest.NewRequest(http.MethodGet, loc, nil)
	gr.Header.Set("Authorization", "Bearer "+tok)
	grr := httptest.NewRecorder()
	h.ServeHTTP(grr, gr)
	body := grr.Body.String()
	if !strings.Contains(body, "by base") || strings.Contains(body, "conic-gradient") {
		t.Error("switched view should render the bar chart, not the wheel")
	}
}

func TestCombineSourcesFlow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()

	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	// Two generic datasets sharing a "base" column.
	_ = dstore.PutMeta(ctx, "ds_pilots", "Pilots", []string{"id", "base"})
	_ = dstore.PutRow(ctx, "ds_pilots", "r1", map[string]string{"id": "1", "base": "Hill"})
	_ = dstore.PutRow(ctx, "ds_pilots", "r2", map[string]string{"id": "2", "base": "Hill"})
	_ = dstore.PutRow(ctx, "ds_pilots", "r3", map[string]string{"id": "3", "base": "Ramstein"})
	_ = dstore.PutMeta(ctx, "ds_wx", "Weather", []string{"base", "temp"})
	_ = dstore.PutRow(ctx, "ds_wx", "w1", map[string]string{"base": "Hill", "temp": "31"})
	_ = dstore.PutRow(ctx, "ds_wx", "w2", map[string]string{"base": "Ramstein", "temp": "19"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_pilots", "Pilots", operators.KindGeneric, "ds_pilots")
	_ = ops.RegisterDataset(ctx, "ds_wx", "Weather", operators.KindGeneric, "ds_wx")
	cmb := combine.NewService(combine.NewMemoryStore(), dsvc)

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, cmb, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)
	get := func(target string) (int, string, string) {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header().Get("Location")
	}

	// The builder lists the two generic sources.
	if code, body, _ := get("/combine/new"); code != http.StatusOK || !strings.Contains(body, "Pilots") || !strings.Contains(body, "Weather") {
		t.Fatalf("combine builder = %d, should list both sources", code)
	}

	// Create the join on base.
	form := url.Values{"name": {"PW"}, "left": {"ds_pilots"}, "left_key": {"base"}, "right": {"ds_wx"}, "right_key": {"base"}}
	cr := httptest.NewRequest(http.MethodPost, "/combine", strings.NewReader(form.Encode()))
	cr.Header.Set("Authorization", "Bearer "+tok)
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, cr)
	if crr.Code != http.StatusSeeOther || crr.Header().Get("Location") != "/datasets/cmb_pw" {
		t.Fatalf("create = %d -> %q", crr.Code, crr.Header().Get("Location"))
	}

	// Opening the combined source shows joined rows (Hill rows carry temp 31).
	code, body, _ := get("/datasets/cmb_pw")
	if code != http.StatusOK {
		t.Fatalf("open combined = %d", code)
	}
	if !strings.Contains(body, "combined") || !strings.Contains(body, ">temp<") || !strings.Contains(body, ">31<") {
		t.Errorf("combined view should show the joined temp column + values")
	}
	// It's read-only: no edit toggle.
	if strings.Contains(body, "Edit rows") {
		t.Error("combined source should be read-only (no Edit rows)")
	}

	// A chart over the combined data works: avg temp by base.
	_, chart, _ := get("/datasets/cmb_pw?vtype=bar&vgroup=base&vval=temp&vagg=avg&view=x")
	if !strings.Contains(chart, "avg of temp by base") {
		t.Error("combined source should support charting the joined columns")
	}

	// It appears in the catalog as a combined source.
	if _, cat, _ := get("/catalog"); !strings.Contains(cat, "cmb_pw") || !strings.Contains(cat, "combined") {
		t.Error("combined source should be listed in the catalog")
	}
}

// TestViewAsPersonaInCatalog verifies an admin's "viewing as" persona carries
// into the catalog: it shows the assumed operator's subscriptions (read-only),
// not the admin's own.
func TestViewAsPersonaInCatalog(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_, _ = ops.CreateOperator(ctx, "s4", "Op Four")
	// s4 is subscribed; the admin (alice) is NOT.
	_ = ops.Subscribe(ctx, "ds_roster", "s4")

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds,
		dsvc, ops, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	admin := kc.SignToken(t, map[string]any{"preferred_username": "alice", "groups": []string{"/UDS Core/Admin"}})

	// Pick up the persona by visiting the dashboard as that operator.
	dreq := httptest.NewRequest(http.MethodGet, "/dashboard?view=operator&as=s4", nil)
	dreq.Header.Set("Authorization", "Bearer "+admin)
	drec := httptest.NewRecorder()
	h.ServeHTTP(drec, dreq)
	var cookie *http.Cookie
	for _, c := range drec.Result().Cookies() {
		if c.Name == "view_as" {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != "s4" {
		t.Fatalf("dashboard should set view_as=s4 cookie, got %v", cookie)
	}

	// The catalog, carrying that cookie, reflects s4's subscriptions + a banner.
	creq := httptest.NewRequest(http.MethodGet, "/catalog", nil)
	creq.Header.Set("Authorization", "Bearer "+admin)
	creq.AddCookie(cookie)
	crec := httptest.NewRecorder()
	h.ServeHTTP(crec, creq)
	body := crec.Body.String()
	if !strings.Contains(body, "Impersonating") || !strings.Contains(body, "s4") {
		t.Error("catalog should show the 'Impersonating s4' banner")
	}
	if !strings.Contains(body, "to 1 of") {
		t.Errorf("catalog should reflect s4's subscriptions (1), not the admin's (0)")
	}
	// Impersonating: actions apply to s4. Unsubscribing here removes s4 (not admin).
	ureq := httptest.NewRequest(http.MethodPost, "/catalog/ds_roster/unsubscribe", nil)
	ureq.Header.Set("Authorization", "Bearer "+admin)
	ureq.AddCookie(cookie)
	h.ServeHTTP(httptest.NewRecorder(), ureq)
	if ops.IsAssigned(ctx, "ds_roster", "s4") {
		t.Error("unsubscribing while impersonating should remove s4's subscription")
	}
	// Re-subscribe while impersonating re-adds s4 (not the admin).
	sreq := httptest.NewRequest(http.MethodPost, "/catalog/ds_roster/subscribe", nil)
	sreq.Header.Set("Authorization", "Bearer "+admin)
	sreq.AddCookie(cookie)
	h.ServeHTTP(httptest.NewRecorder(), sreq)
	if !ops.IsAssigned(ctx, "ds_roster", "s4") || ops.IsAssigned(ctx, "ds_roster", "alice") {
		t.Error("subscribing while impersonating should add s4, not the admin")
	}

	// Exiting (view=admin) clears the persona cookie.
	xreq := httptest.NewRequest(http.MethodGet, "/dashboard?view=admin", nil)
	xreq.Header.Set("Authorization", "Bearer "+admin)
	xreq.AddCookie(cookie)
	xrec := httptest.NewRecorder()
	h.ServeHTTP(xrec, xreq)
	cleared := false
	for _, c := range xrec.Result().Cookies() {
		if c.Name == "view_as" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("view=admin should clear the persona cookie")
	}
}

// TestCombineDeleteRemovesFromCatalog guards the bug where deleting a combined
// source left its catalog/registry entry behind (so it "couldn't be deleted").
func TestCombineDeleteRemovesFromCatalog(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_a", "A", []string{"base", "x"})
	_ = dstore.PutRow(ctx, "ds_a", "r1", map[string]string{"base": "Hill", "x": "1"})
	_ = dstore.PutMeta(ctx, "ds_b", "B", []string{"base", "y"})
	_ = dstore.PutRow(ctx, "ds_b", "r1", map[string]string{"base": "Hill", "y": "2"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_a", "A", operators.KindGeneric, "ds_a")
	_ = ops.RegisterDataset(ctx, "ds_b", "B", operators.KindGeneric, "ds_b")
	cmb := combine.NewService(combine.NewMemoryStore(), dsvc)
	srv, _ := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, cmb, nil)
	h := srv.Routes()
	tok := adminToken(t, kc)
	post := func(target string) {
		r := httptest.NewRequest(http.MethodPost, target, nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	catalog := func() string {
		r := httptest.NewRequest(http.MethodGet, "/catalog", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Body.String()
	}

	form := url.Values{"name": {"AB"}, "left": {"ds_a"}, "left_key": {"base"}, "right": {"ds_b"}, "right_key": {"base"}}
	cr := httptest.NewRequest(http.MethodPost, "/combine", strings.NewReader(form.Encode()))
	cr.Header.Set("Authorization", "Bearer "+tok)
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), cr)
	if !strings.Contains(catalog(), "cmb_ab") {
		t.Fatal("combined source should appear in the catalog after create")
	}
	// Delete it — it must disappear from the catalog (registry entry removed too).
	post("/combine/cmb_ab/delete")
	if strings.Contains(catalog(), "cmb_ab") {
		t.Error("combined source should be gone from the catalog after delete")
	}
	if _, ok, _ := cmb.Get(ctx, "cmb_ab"); ok {
		t.Error("combined spec should be deleted")
	}
}

func TestCombinePreviewAndForgivingMatch(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	// Keys differ only by case/spacing — forgiving matching should still link them.
	_ = dstore.PutMeta(ctx, "ds_roster", "Roster", []string{"name", "base"})
	_ = dstore.PutRow(ctx, "ds_roster", "r1", map[string]string{"name": "A", "base": "Hill AFB"})
	_ = dstore.PutRow(ctx, "ds_roster", "r2", map[string]string{"name": "B", "base": "Edwards"})
	_ = dstore.PutMeta(ctx, "ds_wx", "Weather", []string{"base", "temp"})
	_ = dstore.PutRow(ctx, "ds_wx", "w1", map[string]string{"base": "hill afb", "temp": "31"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_roster", "Roster", operators.KindGeneric, "ds_roster")
	_ = ops.RegisterDataset(ctx, "ds_wx", "Weather", operators.KindGeneric, "ds_wx")
	cmb := combine.NewService(combine.NewMemoryStore(), dsvc)
	srv, _ := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, cmb, nil)
	h := srv.Routes()
	tok := adminToken(t, kc)

	// Preview: 1 of 2 rows match despite case/space differences.
	form := url.Values{"left": {"ds_roster"}, "left_key": {"base"}, "right": {"ds_wx"}, "right_key": {"base"}}
	pr := httptest.NewRequest(http.MethodPost, "/combine/preview", strings.NewReader(form.Encode()))
	pr.Header.Set("Authorization", "Bearer "+tok)
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, pr)
	var pv struct {
		Matched, Unmatched, Total int
		Info                      string
	}
	_ = json.Unmarshal(prr.Body.Bytes(), &pv)
	if pv.Matched != 1 || pv.Total != 2 {
		t.Fatalf("preview matched=%d total=%d, want 1/2 (forgiving match)", pv.Matched, pv.Total)
	}

	// Create + open: the combined view shows the match banner with temp populated.
	cform := url.Values{"name": {"RW"}, "left": {"ds_roster"}, "left_key": {"base"}, "right": {"ds_wx"}, "right_key": {"base"}}
	cr := httptest.NewRequest(http.MethodPost, "/combine", strings.NewReader(cform.Encode()))
	cr.Header.Set("Authorization", "Bearer "+tok)
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crr := httptest.NewRecorder()
	h.ServeHTTP(crr, cr)
	vr := httptest.NewRequest(http.MethodGet, "/datasets/cmb_rw", nil)
	vr.Header.Set("Authorization", "Bearer "+tok)
	vrr := httptest.NewRecorder()
	h.ServeHTTP(vrr, vr)
	body := vrr.Body.String()
	if !strings.Contains(body, "1 of 2 rows matched") || !strings.Contains(body, ">31<") {
		t.Errorf("combined view should show match info + the joined temp value")
	}
}

func TestPublishToDeckFlow(t *testing.T) {
	kc := authtest.NewKeycloak(t)
	defer kc.Close()
	ctx := context.Background()
	ds := datasource.NewService(datasource.NewMemoryStore())
	dstore := dataset.NewMemoryStore()
	_ = dstore.PutMeta(ctx, "ds_r", "Roster", []string{"name", "status"})
	_ = dstore.PutRow(ctx, "ds_r", "r1", map[string]string{"name": "A", "status": "ready"})
	_ = dstore.PutRow(ctx, "ds_r", "r2", map[string]string{"name": "B", "status": "down"})
	dsvc := dataset.NewService(dstore, ds, nil)
	ops := operators.NewService(operators.NewMemoryStore())
	_ = ops.RegisterDataset(ctx, "ds_r", "Roster", operators.KindGeneric, "ds_r")
	dk := deck.NewService(deck.NewMemoryStore())

	srv, err := web.NewServer(kc.Authenticator(t), kc.Config(), ds, dsvc, ops, nil, nil, nil, nil, dk)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	h := srv.Routes()
	tok := adminToken(t, kc)

	// Publish a status-wheel view filtered to status=down into a brand-new deck.
	form := url.Values{
		"title": {"Down roster"}, "new_deck": {"Sync"},
		"col": {"status"}, "val": {"down"},
		"vtype": {"wheel"}, "vgroup": {"status"},
	}
	pr := httptest.NewRequest(http.MethodPost, "/datasets/ds_r/publish", strings.NewReader(form.Encode()))
	pr.Header.Set("Authorization", "Bearer "+tok)
	pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, pr)
	loc := prr.Header().Get("Location")
	if prr.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/decks/dk") {
		t.Fatalf("publish = %d -> %q", prr.Code, loc)
	}

	// The deck renders the published visual live (wheel grouped by status, only
	// the filtered 'down' row → 1 segment).
	dr := httptest.NewRequest(http.MethodGet, loc, nil)
	dr.Header.Set("Authorization", "Bearer "+tok)
	drr := httptest.NewRecorder()
	h.ServeHTTP(drr, dr)
	body := drr.Body.String()
	if !strings.Contains(body, "Down roster") || !strings.Contains(body, "conic-gradient") {
		t.Error("deck should render the published wheel visual")
	}
	if !strings.Contains(body, ">down<") || strings.Contains(body, ">ready<") {
		t.Error("published slide should honor the saved filter (down only)")
	}

	// The deck is listed for everyone.
	lr := httptest.NewRequest(http.MethodGet, "/decks", nil)
	lr.Header.Set("Authorization", "Bearer "+tok)
	lrr := httptest.NewRecorder()
	h.ServeHTTP(lrr, lr)
	if !strings.Contains(lrr.Body.String(), "Sync") {
		t.Error("decks page should list the new deck")
	}
}
