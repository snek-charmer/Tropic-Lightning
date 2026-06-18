package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/combine"
	"github.com/defenseunicorns/keycloak-portal/internal/config"
	"github.com/defenseunicorns/keycloak-portal/internal/dataset"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/deck"
	"github.com/defenseunicorns/keycloak-portal/internal/httpsource"
	"github.com/defenseunicorns/keycloak-portal/internal/operators"
	"github.com/defenseunicorns/keycloak-portal/internal/views"
	"github.com/defenseunicorns/keycloak-portal/internal/weather"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	stateCookie    = "oidc_state"
	nonceCookie    = "oidc_nonce"
	idTokenCookie  = "id_token"  // kept only as a logout hint
	returnToCookie = "return_to" // page to return to after login
	viewAsCookie   = "view_as"   // admin "viewing as" persona (username)
)

// Server holds the dependencies shared by the HTTP handlers.
type Server struct {
	auth        *auth.Authenticator
	cfg         *config.Config
	templates   *template.Template
	dataSources *datasource.Service
	datasets    *dataset.Service
	operators   *operators.Service
	weather     *weather.Service
	httpsource  *httpsource.Service
	views       *views.Service
	combine     *combine.Service
	deck        *deck.Service
}

// NewServer parses templates and returns a Server ready to register routes.
// weather and httpsrc may be nil (no live connectors configured).
func NewServer(authn *auth.Authenticator, cfg *config.Config, ds *datasource.Service, dsets *dataset.Service, ops *operators.Service, wx *weather.Service, httpsrc *httpsource.Service, vw *views.Service, cmb *combine.Service, dk *deck.Service) (*Server, error) {
	// tmpl is captured by the partial func below; assigned after parsing so the
	// shared layout can render a page's content block by name.
	var tmpl *template.Template
	funcs := template.FuncMap{
		"hasPrefix":  strings.HasPrefix,
		"trimPrefix": strings.TrimPrefix,
		// safeurl marks an already-encoded querystring as a trusted URL so
		// html/template normalizes it (preserving & and =) instead of
		// percent-encoding the whole thing into a single broken parameter.
		"safeurl": func(s string) template.URL { return template.URL(s) },
		"partial": func(name string, data any) (template.HTML, error) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
				return "", err
			}
			return template.HTML(buf.String()), nil
		},
	}
	t, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	tmpl = t
	return &Server{auth: authn, cfg: cfg, templates: t, dataSources: ds, datasets: dsets, operators: ops, weather: wx, httpsource: httpsrc, views: vw, combine: cmb, deck: dk}, nil
}

// Routes wires up the HTTP routes and middleware, returning the root handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public routes.
	mux.HandleFunc("GET /", s.handleHome)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)

	// Protected portal page (any authenticated user).
	mux.Handle("GET /dashboard", s.auth.Authenticate(http.HandlerFunc(s.handleDashboard)))

	// Protected JSON API: returns the caller's verified claims and roles.
	mux.Handle("GET /api/me", s.auth.Authenticate(http.HandlerFunc(s.handleMe)))

	// Peat node connection status (any authenticated user) — powers the
	// dashboard status bubble and its live polling.
	mux.Handle("GET /api/peat/status", s.auth.Authenticate(http.HandlerFunc(s.handlePeatStatus)))

	// Admin = "admin" realm role OR membership in the configured admin group.
	adminOnly := s.auth.RequireAdmin()
	mux.Handle("GET /api/admin", s.auth.Authenticate(adminOnly(http.HandlerFunc(s.handleAdmin))))

	// Data sources: admin-only. admin wraps a handler with Authenticate + the
	// admin guard; authed wraps with Authenticate only (any logged-in user).
	admin := func(h http.HandlerFunc) http.Handler {
		return s.auth.Authenticate(adminOnly(h))
	}
	authed := func(h http.HandlerFunc) http.Handler { return s.auth.Authenticate(h) }
	mux.Handle("GET /datasources", admin(s.handleDataSourcesPage))
	mux.Handle("POST /datasources", admin(s.handleDataSourceCreateForm))
	mux.Handle("POST /datasources/{id}/delete", admin(s.handleDataSourceDeleteForm))

	mux.Handle("GET /api/datasources", admin(s.handleDataSourcesList))
	mux.Handle("POST /api/datasources", admin(s.handleDataSourceCreate))
	mux.Handle("DELETE /api/datasources/{id}", admin(s.handleDataSourceDelete))

	// File upload -> preview/format -> ingest as a dataset (admin only).
	mux.Handle("GET /datasources/upload", admin(s.handleUploadPage))
	mux.Handle("POST /datasources/upload", admin(s.handleUploadParse))
	mux.Handle("POST /datasources/preview", admin(s.handleDatasetPreview))
	mux.Handle("POST /datasources/import", admin(s.handleDatasetImport))

	// Live weather connector (Open-Meteo): admin configures locations.
	mux.Handle("POST /datasources/weather", admin(s.handleWeatherCreate))
	// Generic HTTP/JSON connector: admin configures URL + record path + auth.
	mux.Handle("POST /datasources/http", admin(s.handleHTTPSourceCreate))

	// Operators registry (admin-only) — used for the dashboard "view as" preview.
	mux.Handle("GET /operators", admin(s.handleOperatorsPage))
	mux.Handle("POST /operators", admin(s.handleOperatorCreate))
	mux.Handle("POST /operators/{username}/delete", admin(s.handleOperatorDelete))

	// Data-source catalog: any authenticated user browses and self-subscribes.
	mux.Handle("GET /catalog", authed(s.handleCatalogPage))
	mux.Handle("POST /catalog/sync", authed(s.handleCatalogSync))
	mux.Handle("POST /catalog/{key}/subscribe", authed(s.handleSubscribe))
	mux.Handle("POST /catalog/{key}/unsubscribe", authed(s.handleUnsubscribe))

	// Meeting decks: publish filtered visuals to a shared space.
	mux.Handle("GET /decks", authed(s.handleDecksPage))
	mux.Handle("POST /decks", authed(s.handleDeckCreate))
	mux.Handle("GET /decks/{id}", authed(s.handleDeckView))
	mux.Handle("POST /decks/{id}/delete", authed(s.handleDeckDelete))
	mux.Handle("POST /decks/{id}/slides/{sid}/delete", authed(s.handleSlideDelete))
	mux.Handle("POST /datasets/{collection}/publish", authed(s.handlePublish))

	// Combine data sources: any authenticated user joins two sources by a key.
	mux.Handle("GET /combine/new", authed(s.handleCombineNew))
	mux.Handle("POST /combine/preview", authed(s.handleCombinePreview))
	mux.Handle("POST /combine", authed(s.handleCombineCreate))
	mux.Handle("POST /combine/{key}/delete", authed(s.handleCombineDelete))

	// Dataset access (authenticated; per-dataset subscription enforced in-handler).
	mux.Handle("GET /datasets/{collection}", authed(s.handleDatasetView))
	// Operators (assigned) and admins can edit generic datasets.
	mux.Handle("POST /datasets/{collection}/columns/add", authed(s.handleDatasetAddColumn))
	mux.Handle("POST /datasets/{collection}/columns/delete", authed(s.handleDatasetDeleteColumn))
	mux.Handle("POST /datasets/{collection}/rows/add", authed(s.handleDatasetAddRow))
	mux.Handle("POST /datasets/{collection}/rows/update", authed(s.handleDatasetUpdateRow))
	mux.Handle("POST /datasets/{collection}/rows/delete", authed(s.handleDatasetDeleteRow))
	mux.Handle("POST /datasets/{collection}/bulk", authed(s.handleDatasetBulkSave))
	// Per-dataset visualization config (table | wheel).
	mux.Handle("POST /datasets/{collection}/view", authed(s.handleDatasetSetView))
	// Manual refresh of a live connector backing this dataset (weather | http).
	mux.Handle("POST /datasets/{collection}/refresh", authed(s.handleDatasetRefresh))
	// Per-user saved views (named filter + visualization) for a dataset.
	mux.Handle("POST /datasets/{collection}/views", authed(s.handleViewSave))
	mux.Handle("POST /datasets/{collection}/views/{id}/delete", authed(s.handleViewDelete))
	mux.Handle("POST /datasets/{collection}/views/{id}/default", authed(s.handleViewSetDefault))

	return logging(mux)
}

// handleHome shows the landing page with a login button (or a link to the
// dashboard if the visitor already has a valid session cookie).
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	authenticated := false
	if c, err := r.Cookie(auth.AccessTokenCookie); err == nil {
		if _, err := s.auth.VerifyAccessToken(r.Context(), c.Value); err == nil {
			authenticated = true
		}
	}
	s.render(w, r, "home.html", "Sign in", "home", map[string]any{"Authenticated": authenticated})
}

// handleLogin starts the authorization code flow: generate CSRF state + nonce,
// store them in short-lived cookies, and redirect to Keycloak.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString()
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	s.setCookie(w, stateCookie, state, 10*time.Minute)
	s.setCookie(w, nonceCookie, nonce, 10*time.Minute)

	// Remember where to return after login (set by the auth middleware's redirect).
	if rt := auth.SafeLocalPath(r.URL.Query().Get("return_to")); rt != "" {
		s.setCookie(w, returnToCookie, rt, 10*time.Minute)
	} else {
		s.clearCookie(w, returnToCookie)
	}

	http.Redirect(w, r, s.auth.AuthCodeURL(state, nonce), http.StatusFound)
}

// handleCallback completes the flow: validate state, exchange the code, verify
// the ID token nonce, then store the access token in a session cookie.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		http.Error(w, "authorization error: "+errParam+" "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}

	stateCookieVal, err := r.Cookie(stateCookie)
	if err != nil || stateCookieVal.Value == "" || stateCookieVal.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	token, err := s.auth.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusBadGateway)
		return
	}
	idToken, err := s.auth.VerifyIDToken(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify id token: "+err.Error(), http.StatusBadGateway)
		return
	}

	nonceCookieVal, err := r.Cookie(nonceCookie)
	if err != nil || idToken.Nonce != nonceCookieVal.Value {
		http.Error(w, "invalid nonce", http.StatusBadRequest)
		return
	}

	// Persist the access token for browser navigation, and the ID token for
	// use as a logout hint. Clear the transient state/nonce cookies.
	tokenTTL := time.Until(token.Expiry)
	if tokenTTL <= 0 {
		tokenTTL = time.Hour
	}
	s.setCookie(w, auth.AccessTokenCookie, token.AccessToken, tokenTTL)
	s.setCookie(w, idTokenCookie, rawIDToken, tokenTTL)
	// Store the refresh token so the session renews silently when the access
	// token expires (instead of bouncing the user to the dashboard).
	if token.RefreshToken != "" {
		s.setCookie(w, auth.RefreshTokenCookie, token.RefreshToken, 12*time.Hour)
	}
	s.clearCookie(w, stateCookie)
	s.clearCookie(w, nonceCookie)

	// Return to the page that triggered login, if any.
	dest := "/dashboard"
	if c, err := r.Cookie(returnToCookie); err == nil {
		if rt := auth.SafeLocalPath(c.Value); rt != "" {
			dest = rt
		}
		s.clearCookie(w, returnToCookie)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handleLogout clears local cookies and redirects to Keycloak's RP-initiated
// logout endpoint so the SSO session is ended too.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idHint string
	if c, err := r.Cookie(idTokenCookie); err == nil {
		idHint = c.Value
	}
	s.clearCookie(w, auth.AccessTokenCookie)
	s.clearCookie(w, auth.RefreshTokenCookie)
	s.clearCookie(w, idTokenCookie)
	http.Redirect(w, r, s.auth.LogoutURL(idHint), http.StatusFound)
}

// handleDashboard renders the authenticated portal page showing user identity
// and the roles Keycloak issued.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	clientRoles := map[string][]string{}
	for client, ra := range claims.ResourceAccess {
		if len(ra.Roles) > 0 {
			clientRoles[client] = ra.Roles
		}
	}

	// Initial peat-node connection state for the status bubble (the page also
	// polls /api/peat/status to keep it live).
	peat, connected := s.peatStatus(r.Context())

	// Persona view: admins can preview a specific operator's view. The choice is
	// remembered in a cookie so it persists across pages (catalog, datasets) —
	// see previewUser. ?view=admin clears it; ?view=operator&as=<user> sets it.
	isAdmin := s.auth.IsAdmin(claims)
	self := s.operatorName(claims)
	view := "operator"
	previewAs := self
	var opList []operators.Operator
	if isAdmin {
		opList, _ = s.operators.ListOperators(r.Context())
		q := r.URL.Query()
		switch {
		case q.Get("view") == "operator":
			view = "operator"
			as := q.Get("as")
			if as == "" {
				if c, err := r.Cookie(viewAsCookie); err == nil {
					as = c.Value
				}
			}
			if as != "" && as != self {
				previewAs = as
				s.setCookie(w, viewAsCookie, as, 8*time.Hour)
			} else {
				previewAs = self // preview own operator view (no persona)
			}
		case q.Get("view") == "admin":
			view = "admin"
			s.clearCookie(w, viewAsCookie)
		default:
			// No explicit choice: honor an active persona cookie if present.
			if c, err := r.Cookie(viewAsCookie); err == nil && c.Value != "" && c.Value != self {
				view, previewAs = "operator", c.Value
			} else {
				view = "admin"
			}
		}
	}

	// Datasets assigned to the previewed user (the operator view's "Your datasets").
	myDatasets, _ := s.operators.DatasetsForOperator(r.Context(), previewAs)

	s.render(w, r, "dashboard.html", "Dashboard", "dashboard", map[string]any{
		"Username":      firstNonEmpty(claims.PreferredUsername, claims.Name, claims.Subject),
		"Email":         claims.Email,
		"RealmRoles":    claims.AllRealmRoles(),
		"Groups":        claims.AllGroups(),
		"ClientRoles":   clientRoles,
		"IsAdmin":       isAdmin,
		"View":          view, // "admin" | "operator"
		"Operators":     opList,
		"PreviewAs":     previewAs,
		"MyDatasets":    myDatasets,
		"PeatConnected": connected,
		"Peat":          peat,
	})
}

// peatStatus probes the peat node, bounded by a short timeout so the page never
// hangs when the node is unreachable. connected is true when the node answered.
func (s *Server) peatStatus(parent context.Context) (datasource.MeshStatus, bool) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	st, err := s.dataSources.Status(ctx)
	return st, err == nil
}

// handlePeatStatus reports the peat-node connection as JSON (polled by the
// dashboard bubble). connected=false means the node is unreachable.
func (s *Server) handlePeatStatus(w http.ResponseWriter, r *http.Request) {
	st, connected := s.peatStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"connected":       connected,
		"node_id":         st.NodeID,
		"sync_active":     st.SyncActive,
		"connected_peers": st.ConnectedPeers,
	})
}

// handleMe returns the verified claims as JSON — the bearer-token API path.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	writeJSON(w, http.StatusOK, claims)
}

// handleAdmin is an example endpoint guarded by RequireRealmRole("admin").
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "welcome, admin",
		"user":    firstNonEmpty(claims.PreferredUsername, claims.Subject),
	})
}

// --- data sources (admin only) ---

// handleDataSourcesPage renders the admin page: a form to add a data source and
// a table of existing ones with their sync status.
func (s *Server) handleDataSourcesPage(w http.ResponseWriter, r *http.Request) {
	sources, err := s.dataSources.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list data sources: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Best-effort mesh status banner; never block the page on it.
	status, statusErr := s.dataSources.Status(r.Context())
	var wxConnectors []weather.Connector
	if s.weather != nil {
		wxConnectors, _ = s.weather.ListConnectors(r.Context())
	}
	var httpConnectors []httpsource.Connector
	if s.httpsource != nil {
		httpConnectors, _ = s.httpsource.ListConnectors(r.Context())
	}
	s.render(w, r, "datasources.html", "Data sources", "datasources", map[string]any{
		"Sources":           sources,
		"KnownTypes":        datasource.KnownTypes,
		"Error":             r.URL.Query().Get("error"),
		"Created":           r.URL.Query().Get("ok") == "created",
		"Mesh":              status,
		"MeshReachable":     statusErr == nil,
		"WeatherEnabled":    s.weather != nil,
		"WeatherConnectors": wxConnectors,
		"HTTPEnabled":       s.httpsource != nil,
		"HTTPConnectors":    httpConnectors,
		"HTTPAuthTypes":     httpsource.AuthTypes(),
	})
}

// handleDataSourceCreateForm handles the HTML form submission.
func (s *Server) handleDataSourceCreateForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/datasources?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
		return
	}
	in := datasource.Input{
		Name:      r.PostFormValue("name"),
		Type:      r.PostFormValue("type"),
		Endpoint:  r.PostFormValue("endpoint"),
		SecretRef: r.PostFormValue("secret_ref"),
		Enabled:   r.PostFormValue("enabled") == "on",
	}
	if _, err := s.dataSources.Create(r.Context(), in); err != nil {
		http.Redirect(w, r, "/datasources?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/datasources?ok=created", http.StatusSeeOther)
}

// handleDataSourceDeleteForm handles the per-row delete button.
func (s *Server) handleDataSourceDeleteForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.dataSources.Delete(r.Context(), id); err != nil && !errors.Is(err, datasource.ErrNotFound) {
		http.Redirect(w, r, "/datasources?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/datasources", http.StatusSeeOther)
}

// handleDataSourcesList is the JSON API listing.
func (s *Server) handleDataSourcesList(w http.ResponseWriter, r *http.Request) {
	sources, err := s.dataSources.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if sources == nil {
		sources = []datasource.DataSource{}
	}
	writeJSON(w, http.StatusOK, sources)
}

// handleDataSourceCreate is the JSON API create endpoint.
func (s *Server) handleDataSourceCreate(w http.ResponseWriter, r *http.Request) {
	var in datasource.Input
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	ds, err := s.dataSources.Create(r.Context(), in)
	if err != nil {
		var ve datasource.ValidationError
		if errors.As(err, &ve) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": ve.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ds)
}

// handleDataSourceDelete is the JSON API delete endpoint.
func (s *Server) handleDataSourceDelete(w http.ResponseWriter, r *http.Request) {
	err := s.dataSources.Delete(r.Context(), r.PathValue("id"))
	if errors.Is(err, datasource.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- file upload -> dataset (admin only) ---

const maxUploadBytes = 12 << 20 // 12 MiB

// handleUploadPage redirects to the data sources page, where file upload is one
// of the inline "add a source" options.
func (s *Server) handleUploadPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/datasources#file", http.StatusFound)
}

// handleUploadParse accepts a multipart file, parses it, holds it for preview,
// and returns the columns + a sample of rows as JSON for the in-browser preview.
func (s *Server) handleUploadParse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file too large or invalid (max 12 MiB)"})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file provided"})
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxUploadBytes))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	token, parsed, err := s.datasets.Stage(header.Filename, data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, previewJSON(token, parsed))
}

// handleDatasetPreview re-parses a held upload with a chosen delimiter so the
// admin can fix a mis-delimited file before importing.
func (s *Server) handleDatasetPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
		return
	}
	parsed, err := s.datasets.Preview(r.PostFormValue("token"), r.PostFormValue("delimiter"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, previewJSON(r.PostFormValue("token"), parsed))
}

// previewJSON shapes a parsed upload for the in-browser preview.
func previewJSON(token string, parsed dataset.Parsed) map[string]any {
	sample := parsed.Rows
	if len(sample) > 20 {
		sample = sample[:20]
	}
	return map[string]any{
		"token":            token,
		"filename":         parsed.Filename,
		"columns":          parsed.Columns,
		"rows":             sample,
		"total":            len(parsed.Rows),
		"delimiter":        parsed.Delimiter, // "" for xlsx
		"delimiterOptions": dataset.DelimiterNames(),
	}
}

// handleDatasetImport ingests the held upload, keeping the submitted columns.
func (s *Server) handleDatasetImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/datasources/upload?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
		return
	}
	token := r.PostFormValue("token")
	name := r.PostFormValue("name")
	delimiter := r.PostFormValue("delimiter")
	keep := r.PostForm["col"] // checked columns to keep

	res, err := s.datasets.Import(r.Context(), token, name, delimiter, keep)
	if err != nil {
		http.Redirect(w, r, "/datasources/upload?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// Register it as an assignable dataset (idempotent; preserves assignments).
	if err := s.operators.RegisterDataset(r.Context(), res.Collection, name, operators.KindGeneric, res.Collection); err != nil {
		slog.Warn("register dataset", "err", err)
	}
	dest := "/datasets/" + res.Collection + "?imported=" + strconv.Itoa(res.Imported)
	if res.Capped {
		dest += "&capped=" + strconv.Itoa(res.Total)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// handleWeatherCreate configures a live Open-Meteo weather source from a name
// and a textarea of "label,latitude,longitude" lines, registers it as an
// assignable dataset, and seeds it with a first fetch.
func (s *Server) handleWeatherCreate(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		http.Redirect(w, r, "/datasources?error="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if s.weather == nil {
		fail("weather connector is not configured on this deployment")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("invalid form")
		return
	}
	name := r.PostFormValue("name")
	locs, err := parseLocations(r.PostFormValue("locations"))
	if err != nil {
		fail(err.Error())
		return
	}
	c, err := s.weather.CreateConnector(r.Context(), name, locs)
	if err != nil {
		fail(err.Error())
		return
	}
	// Register as an assignable, viewable dataset + a catalog entry.
	if err := s.operators.RegisterDataset(r.Context(), c.Collection, c.Name, operators.KindGeneric, c.Collection); err != nil {
		slog.Warn("register weather dataset", "err", err)
	}
	if _, err := s.dataSources.Create(r.Context(), datasource.Input{
		Name: c.Name, Type: "weather", Endpoint: "dataset://" + c.Collection, Enabled: true,
	}); err != nil {
		slog.Warn("register weather catalog entry", "err", err)
	}
	http.Redirect(w, r, "/datasets/"+c.Collection, http.StatusSeeOther)
}

// parseLocations reads "label,lat,lon" lines into weather locations.
func parseLocations(raw string) ([]weather.Location, error) {
	var out []weather.Location
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			return nil, fmt.Errorf("line %d: expected \"label, latitude, longitude\"", i+1)
		}
		lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[len(parts)-2]), 64)
		lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[len(parts)-1]), 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("line %d: latitude/longitude must be numbers", i+1)
		}
		label := strings.TrimSpace(strings.Join(parts[:len(parts)-2], ","))
		out = append(out, weather.Location{Label: label, Lat: lat, Lon: lon})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("add at least one location (label, latitude, longitude)")
	}
	return out, nil
}

// handleHTTPSourceCreate configures a generic HTTP/JSON connector, fetches a
// first snapshot, registers it as an assignable dataset, and opens it.
func (s *Server) handleHTTPSourceCreate(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		http.Redirect(w, r, "/datasources?error="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	if s.httpsource == nil {
		fail("HTTP connector is not configured on this deployment")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail("invalid form")
		return
	}
	// Bound the create (it does a live fetch) so a slow API can't hang the request.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	c, err := s.httpsource.CreateConnector(ctx, httpsource.Input{
		Name:       r.PostFormValue("name"),
		URL:        r.PostFormValue("url"),
		RecordPath: r.PostFormValue("record_path"),
		AuthType:   r.PostFormValue("auth_type"),
		HeaderName: r.PostFormValue("header_name"),
		AuthValue:  r.PostFormValue("auth_value"),
	})
	if err != nil {
		fail(err.Error())
		return
	}
	if err := s.operators.RegisterDataset(r.Context(), c.Collection, c.Name, operators.KindGeneric, c.Collection); err != nil {
		slog.Warn("register http dataset", "err", err)
	}
	if _, err := s.dataSources.Create(r.Context(), datasource.Input{
		Name: c.Name, Type: "http", Endpoint: "dataset://" + c.Collection, Enabled: true,
	}); err != nil {
		slog.Warn("register http catalog entry", "err", err)
	}
	http.Redirect(w, r, "/datasets/"+c.Collection, http.StatusSeeOther)
}

// handleDatasetRefresh re-pulls a live connector (weather or HTTP/JSON) backing
// this dataset, then returns to the viewer. No-op for plain uploaded datasets.
func (s *Server) handleDatasetRefresh(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		if s.weather != nil {
			if found, err := s.weather.RefreshOne(ctx, c); err != nil {
				return err
			} else if found {
				return nil
			}
		}
		if s.httpsource != nil {
			if found, err := s.httpsource.RefreshOne(ctx, c); err != nil {
				return err
			} else if found {
				return nil
			}
		}
		return fmt.Errorf("this dataset has no live connector to refresh")
	})
}

// handleDatasetView renders an ingested dataset's rows (kept columns).
func (s *Server) handleDatasetView(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		s.forbidden(w, r)
		return
	}
	ctx := r.Context()
	owner := s.effectiveUser(r)
	qry := r.URL.Query()
	col := qry.Get("col")
	val := qry.Get("val")
	q := qry.Get("q")
	vtype := qry.Get("vtype") // per-view visualization override
	vgroup := qry.Get("vgroup")
	vval := qry.Get("vval")
	vagg := qry.Get("vagg")
	activeView := qry.Get("view") // a saved view id, or "none", or ""
	editMode := qry.Get("edit") == "1"

	// Saved views (private to the user). When the dataset is opened "clean" — no
	// filter/viz/view/edit params — auto-apply the user's default view so they
	// don't have to re-filter every time.
	var savedViews []views.View
	if s.views != nil {
		savedViews, _ = s.views.List(ctx, owner, collection)
		clean := col == "" && val == "" && q == "" && vtype == "" && vgroup == "" && vval == "" && vagg == "" && activeView == "" && !editMode
		if clean {
			if def, ok, _ := s.views.Default(ctx, owner, collection); ok {
				http.Redirect(w, r, "/datasets/"+collection+"?"+viewQuery(def), http.StatusFound)
				return
			}
		}
	}

	// A combined source is virtual: compute its joined rows live. It's read-only
	// (derived) so row/column editing and connector refresh don't apply.
	var name string
	var cols []string
	var rows []dataset.Row
	var err error
	combined := false
	var matchInfo string
	if s.combine != nil {
		if _, ok, _ := s.combine.Get(ctx, collection); ok {
			combined = true
			editMode = false
			var res combine.Result
			res, err = s.combine.Compute(ctx, collection)
			name, cols, rows = res.Name, res.Columns, res.Rows
			if err == nil {
				matchInfo = combineMatchInfo(res)
			}
		}
	}
	if !combined {
		name, cols, rows, err = s.datasets.View(ctx, collection)
	}
	if err != nil {
		http.Error(w, "failed to load dataset: "+err.Error(), http.StatusNotFound)
		return
	}

	// Generic row filter: a column "contains" match and/or a global search.
	filtered := rows
	if col != "" && val != "" || q != "" {
		filtered = filtered[:0:0]
		for _, row := range rows {
			if rowMatches(row.Fields, col, val, q) {
				filtered = append(filtered, row)
			}
		}
	}

	shown := filtered
	if len(shown) > datasetDisplayLimit {
		shown = shown[:datasetDisplayLimit]
	}

	// Effective visualization: a saved view's override (v* params in the URL)
	// wins; otherwise fall back to the dataset's own shared setting.
	effType, effGroup, effVal, effAgg := vtype, vgroup, vval, vagg
	if effType == "" {
		dv := s.datasetView(ctx, collection)
		effType, effGroup, effVal, effAgg = dv.Type, dv.GroupBy, dv.ValueCol, dv.Agg
	}
	if effAgg == "" {
		effAgg = "count"
	}
	var segments []wheelSegment
	var gradient template.CSS
	var bars []barVM
	var stats statsVM
	var line lineVM
	var hasLine bool
	switch effType {
	case "wheel":
		if effGroup != "" {
			segments, gradient = computeWheel(filtered, effGroup)
		}
	case "bar":
		bars = computeBars(filtered, effGroup, effVal, effAgg)
	case "line":
		line, hasLine = computeLine(filtered, effGroup, effVal, effAgg)
	case "stats":
		stats = computeStats(filtered, effVal)
	}

	// View models: an apply querystring + active flag for each saved view.
	type savedViewVM struct {
		ID, Name string
		Default  bool
		Active   bool
		Query    string
	}
	vms := make([]savedViewVM, 0, len(savedViews))
	for _, v := range savedViews {
		vms = append(vms, savedViewVM{ID: v.ID, Name: v.Name, Default: v.Default, Active: v.ID == activeView, Query: viewQuery(v)})
	}

	s.render(w, r, "dataset_view.html", name, "datasources", map[string]any{
		"Collection":    collection,
		"Name":          name,
		"Columns":       cols,
		"Rows":          shown,
		"Shown":         len(shown),
		"Total":         len(filtered),
		"GrandTotal":    len(rows),
		"FilterCol":     col,
		"FilterVal":     val,
		"FilterQuery":   q,
		"FilterActive":  (col != "" && val != "") || q != "",
		"EditMode":      editMode,
		"BackQuery":     r.URL.RawQuery, // preserve filter+view+edit on edit actions
		"Imported":      qry.Get("imported"),
		"Capped":        qry.Get("capped"),
		"Error":         qry.Get("error"),
		"ViewType":      effType,
		"ViewGroupBy":   effGroup,
		"ViewValueCol":  effVal,
		"ViewAgg":       effAgg,
		"WheelSegments": segments,
		"WheelGradient": gradient,
		"Bars":          bars,
		"Stats":         stats,
		"Line":          line,
		"HasLine":       hasLine,
		"IsAdmin":       s.auth.IsAdmin(claimsOf(r)),
		// wx_ (weather) and api_ (HTTP/JSON) datasets are backed by a live
		// connector and can be re-pulled on demand. Combined sources are virtual
		// (computed live) and read-only.
		"LiveConnector": !combined && (strings.HasPrefix(collection, "wx_") || strings.HasPrefix(collection, "api_")),
		"ReadOnly":      combined,
		"Combined":      combined,
		"MatchInfo":     matchInfo,
		"SavedViews":    vms,
		"HasViews":      s.views != nil,
		"ActiveView":    activeView,
		"CanPublish":    s.deck != nil,
		"Decks":         s.decksFor(ctx),
	})
}

// decksFor lists decks for the publish control (nil-safe; empty on error).
func (s *Server) decksFor(ctx context.Context) []deck.Deck {
	if s.deck == nil {
		return nil
	}
	decks, _ := s.deck.ListDecks(ctx)
	return decks
}

// viewQuery encodes a saved view as the querystring that re-applies it.
func viewQuery(v views.View) string {
	q := url.Values{}
	if v.FilterCol != "" {
		q.Set("col", v.FilterCol)
	}
	if v.FilterVal != "" {
		q.Set("val", v.FilterVal)
	}
	if v.Query != "" {
		q.Set("q", v.Query)
	}
	if v.ViewType != "" {
		q.Set("vtype", v.ViewType)
	}
	if v.GroupBy != "" {
		q.Set("vgroup", v.GroupBy)
	}
	if v.ValueCol != "" {
		q.Set("vval", v.ValueCol)
	}
	if v.Agg != "" {
		q.Set("vagg", v.Agg)
	}
	q.Set("view", v.ID)
	return q.Encode()
}

// handleViewSave saves the current filter + visualization as a named private
// view for the calling user, then opens it.
func (s *Server) handleViewSave(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		s.forbidden(w, r)
		return
	}
	if s.views == nil {
		http.Redirect(w, r, "/datasets/"+collection, http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	v := views.View{
		Owner:      s.effectiveUser(r),
		Collection: collection,
		Name:       r.PostFormValue("name"),
		Default:    r.PostFormValue("default") == "on",
		FilterCol:  r.PostFormValue("col"),
		FilterVal:  r.PostFormValue("val"),
		Query:      r.PostFormValue("q"),
		ViewType:   r.PostFormValue("vtype"),
		GroupBy:    r.PostFormValue("vgroup"),
		ValueCol:   r.PostFormValue("vval"),
		Agg:        r.PostFormValue("vagg"),
	}
	saved, err := s.views.Save(r.Context(), v)
	if err != nil {
		// Return to the current filter with the error shown.
		back := viewQueryFromForm(r)
		http.Redirect(w, r, "/datasets/"+collection+"?"+back+"&error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/datasets/"+collection+"?"+viewQuery(saved), http.StatusSeeOther)
}

// handleViewDelete removes one of the caller's saved views.
func (s *Server) handleViewDelete(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) || s.views == nil {
		s.forbidden(w, r)
		return
	}
	if err := s.views.Delete(r.Context(), s.effectiveUser(r), r.PathValue("id")); err != nil && !errors.Is(err, views.ErrNotFound) {
		http.Redirect(w, r, "/datasets/"+collection+"?view=none&error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/datasets/"+collection+"?view=none", http.StatusSeeOther)
}

// handleViewSetDefault sets (default=on) or clears (default=off) the caller's
// default view for this dataset.
func (s *Server) handleViewSetDefault(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) || s.views == nil {
		s.forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	owner := s.effectiveUser(r)
	id := r.PathValue("id")
	var err error
	if r.PostFormValue("default") == "off" {
		err = s.views.SetDefault(r.Context(), owner, collection, "")
		id = "" // clearing -> open unfiltered
	} else {
		err = s.views.SetDefault(r.Context(), owner, collection, id)
	}
	if err != nil {
		http.Redirect(w, r, "/datasets/"+collection+"?view=none&error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if id == "" {
		http.Redirect(w, r, "/datasets/"+collection+"?view=none", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/datasets/"+collection+"?view="+url.QueryEscape(id), http.StatusSeeOther)
}

// viewQueryFromForm rebuilds the filter+viz querystring from a posted form (used
// to return to the same view after an error).
func viewQueryFromForm(r *http.Request) string {
	q := url.Values{}
	for _, k := range []string{"col", "val", "q", "vtype", "vgroup", "vval", "vagg"} {
		if v := r.PostFormValue(k); v != "" {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

// datasetView returns the dataset's visualization config (defaulting to table).
func (s *Server) datasetView(ctx context.Context, collection string) operators.ViewConfig {
	d, err := s.operators.GetDataset(ctx, collection)
	if err != nil || d.View.Type == "" {
		return operators.ViewConfig{Type: "table"}
	}
	return d.View
}

// handleDatasetSetView updates how a dataset is visualized (admins + assigned
// operators), then returns to the viewer.
func (s *Server) handleDatasetSetView(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		s.forbidden(w, r)
		return
	}
	_ = r.ParseForm()
	vc := operators.ViewConfig{
		Type:     r.PostFormValue("type"),
		GroupBy:  r.PostFormValue("group_by"),
		ValueCol: r.PostFormValue("value_col"),
		Agg:      r.PostFormValue("agg"),
	}
	dest := "/datasets/" + collection + "?" + viewRedirectQuery(r, vc)
	if err := s.operators.SetView(r.Context(), collection, vc); err != nil {
		http.Redirect(w, r, dest+"&error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// Redirect with the chosen visualization as an explicit override (preserving
	// any active filter) so the selection is shown immediately — otherwise a
	// stale vtype carried in the form's action query would mask the change.
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// viewRedirectQuery preserves the active filter (col/val/q from the action
// query) and applies the chosen visualization as an override.
func viewRedirectQuery(r *http.Request, vc operators.ViewConfig) string {
	q := url.Values{}
	src := r.URL.Query()
	for _, k := range []string{"col", "val", "q"} {
		if v := src.Get(k); v != "" {
			q.Set(k, v)
		}
	}
	vt := strings.TrimSpace(vc.Type)
	if vt == "" {
		vt = "table"
	}
	q.Set("vtype", vt) // always set (incl. table) so it overrides any stale value
	if vc.GroupBy != "" {
		q.Set("vgroup", vc.GroupBy)
	}
	if vc.ValueCol != "" {
		q.Set("vval", vc.ValueCol)
	}
	if vc.Agg != "" {
		q.Set("vagg", vc.Agg)
	}
	return q.Encode()
}

// wheelSegment is one slice of a status wheel: a distinct value and its share.
type wheelSegment struct {
	Label string
	Count int
	Pct   float64
	Color string
}

// wheelPalette colors wheel slices, cycling if there are more values than colors.
var wheelPalette = []string{
	"#4636f5", "#22b8cf", "#51cf66", "#fcc419", "#ff6b6b",
	"#845ef7", "#ff922b", "#20c997", "#f06595", "#868e96",
}

// computeWheel groups rows by a column into wheel slices (largest first) and
// builds the conic-gradient backing the donut.
func computeWheel(rows []dataset.Row, groupBy string) ([]wheelSegment, template.CSS) {
	counts := map[string]int{}
	for _, r := range rows {
		v := strings.TrimSpace(r.Fields[groupBy])
		if v == "" {
			v = "(blank)"
		}
		counts[v]++
	}
	if len(counts) == 0 {
		return nil, ""
	}
	segs := make([]wheelSegment, 0, len(counts))
	for label, n := range counts {
		segs = append(segs, wheelSegment{Label: label, Count: n})
	}
	// Largest first, then alphabetical, for a stable, readable order.
	sort.Slice(segs, func(i, j int) bool {
		if segs[i].Count != segs[j].Count {
			return segs[i].Count > segs[j].Count
		}
		return segs[i].Label < segs[j].Label
	})

	total := len(rows)
	var b strings.Builder
	b.WriteString("conic-gradient(")
	acc := 0.0
	for i := range segs {
		segs[i].Color = wheelPalette[i%len(wheelPalette)]
		if total > 0 {
			segs[i].Pct = float64(segs[i].Count) / float64(total) * 100
		}
		start := acc
		acc += segs[i].Pct
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s %.3f%% %.3f%%", segs[i].Color, start, acc)
	}
	b.WriteString(")")
	return segs, template.CSS(b.String())
}

// claimsOf is a small helper for templates that need the admin flag.
func claimsOf(r *http.Request) *auth.Claims {
	c, _ := auth.ClaimsFromContext(r.Context())
	return c
}

// dataset edits (assigned operators + admins). Each checks access, mutates, and
// redirects back to the viewer.

func (s *Server) datasetEdit(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, collection string) error) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		s.forbidden(w, r)
		return
	}
	// Preserve the current view (edit mode + filter) carried in the action query.
	dest := "/datasets/" + collection
	if r.URL.RawQuery != "" {
		dest += "?" + r.URL.RawQuery
	}
	back := func(errMsg string) {
		sep := "?"
		if r.URL.RawQuery != "" {
			sep = "&"
		}
		http.Redirect(w, r, dest+sep+"error="+url.QueryEscape(errMsg), http.StatusSeeOther)
	}
	if err := r.ParseForm(); err != nil {
		back("invalid form")
		return
	}
	if err := fn(r.Context(), collection); err != nil {
		back(err.Error())
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) handleDatasetAddColumn(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		return s.datasets.AddColumn(ctx, c, r.PostFormValue("name"))
	})
}

func (s *Server) handleDatasetDeleteColumn(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		return s.datasets.DeleteColumn(ctx, c, r.PostFormValue("name"))
	})
}

func (s *Server) handleDatasetAddRow(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		// Column inputs are named "f_<column>".
		values := map[string]string{}
		for k, v := range r.PostForm {
			if name, ok := strings.CutPrefix(k, "f_"); ok && len(v) > 0 {
				values[name] = v[0]
			}
		}
		return s.datasets.AddRow(ctx, c, values)
	})
}

func (s *Server) handleDatasetUpdateRow(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		values := map[string]string{}
		for k, v := range r.PostForm {
			if name, ok := strings.CutPrefix(k, "f_"); ok && len(v) > 0 {
				values[name] = v[0]
			}
		}
		return s.datasets.UpdateRow(ctx, c, r.PostFormValue("id"), values)
	})
}

func (s *Server) handleDatasetDeleteRow(w http.ResponseWriter, r *http.Request) {
	s.datasetEdit(w, r, func(ctx context.Context, c string) error {
		return s.datasets.DeleteRow(ctx, c, r.PostFormValue("id"))
	})
}

// handleDatasetBulkSave applies many row edits (update/add/delete) from a JSON
// body in one request, so the editor can "Save all" once.
func (s *Server) handleDatasetBulkSave(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not assigned to this dataset"})
		return
	}
	var req struct {
		Rows    []dataset.RowEdit `json:"rows"`
		Deletes []string          `json:"deletes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxUploadBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	res, err := s.datasets.BulkSave(r.Context(), collection, req.Rows, req.Deletes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// rowMatches applies the generic dataset filter to a row.
func rowMatches(row map[string]string, col, val, q string) bool {
	if col != "" && val != "" {
		if !strings.Contains(strings.ToLower(row[col]), strings.ToLower(val)) {
			return false
		}
	}
	if q != "" {
		found := false
		for _, v := range row {
			if strings.Contains(strings.ToLower(v), strings.ToLower(q)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// operatorName is the identity used for assignment checks (Keycloak username).
func (s *Server) operatorName(claims *auth.Claims) string {
	if claims == nil {
		return ""
	}
	return firstNonEmpty(claims.PreferredUsername, claims.Subject)
}

// previewUser returns the identity to act "as": the admin's active "viewing as"
// persona (from the view_as cookie) when set, otherwise the caller's own
// username. persona is true when impersonating someone else. While a persona is
// active, the admin impersonates that user — per-user actions (subscribe, saved
// views, combine ownership) apply to them, not to the admin.
func (s *Server) previewUser(r *http.Request) (user string, persona bool) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	self := s.operatorName(claims)
	if claims != nil && s.auth.IsAdmin(claims) {
		if c, err := r.Cookie(viewAsCookie); err == nil && c.Value != "" && c.Value != self {
			return c.Value, true
		}
	}
	return self, false
}

// effectiveUser is the identity per-user actions apply to: the impersonated
// persona when active, else the caller.
func (s *Server) effectiveUser(r *http.Request) string {
	u, _ := s.previewUser(r)
	return u
}

// canAccessDataset is true for admins, or operators the dataset is assigned to.
func (s *Server) canAccessDataset(r *http.Request, key string) bool {
	claims, _ := auth.ClaimsFromContext(r.Context())
	if s.auth.IsAdmin(claims) {
		return true
	}
	return s.operators.IsAssigned(r.Context(), key, s.operatorName(claims))
}

// forbidden renders a 403 (HTML or JSON by Accept).
func (s *Server) forbidden(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<p>You're not subscribed to this data source. <a href=\"/catalog\">Browse &amp; subscribe</a> · <a href=\"/dashboard\">Back</a></p>"))
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "not assigned to this dataset"})
}

// --- operators & assignments (admin only) ---

// reconcileDatasets ensures the registry contains every dataset known to the
// node — catalog (dataset://) entries, combined sources, AND any dataset
// collection present in the peat node (e.g. synced in from a peer that this app
// has no local record of) — so they all show up in the catalog. Idempotent;
// preserves subscriptions. Returns the number of *newly discovered* datasets
// (ones that weren't already registered).
func (s *Server) reconcileDatasets(ctx context.Context) int {
	// Drop the legacy "pilots" demo dataset if it lingers from older versions.
	_ = s.operators.DeleteDataset(ctx, "pilots")

	known := map[string]bool{}
	if existing, err := s.operators.ListDatasets(ctx); err == nil {
		for _, d := range existing {
			known[d.Key] = true
		}
	}

	if sources, err := s.dataSources.List(ctx); err == nil {
		for _, d := range sources {
			if c, ok := strings.CutPrefix(d.Endpoint, "dataset://"); ok && c != "" {
				if err := s.operators.RegisterDataset(ctx, c, d.Name, operators.KindGeneric, c); err != nil {
					slog.Warn("reconcile dataset", "collection", c, "err", err)
				}
			}
		}
	} else {
		slog.Warn("reconcile: list data sources", "err", err)
	}

	// Combined sources are virtual datasets; register them so they're listed.
	if s.combine != nil {
		if combos, err := s.combine.List(ctx); err == nil {
			for _, c := range combos {
				if err := s.operators.RegisterDataset(ctx, c.Key, c.Name, operators.KindCombined, c.Key); err != nil {
					slog.Warn("reconcile combined source", "key", c.Key, "err", err)
				}
			}
		} else {
			slog.Warn("reconcile: list combined sources", "err", err)
		}
	}

	// Discover dataset collections sitting in the peat node (incl. mesh-synced
	// ones) that aren't registered yet, and add them so users can subscribe.
	added := 0
	if refs, err := s.datasets.Discover(ctx); err == nil {
		for _, ref := range refs {
			if known[ref.Collection] {
				continue
			}
			if err := s.operators.RegisterDataset(ctx, ref.Collection, ref.Name, operators.KindGeneric, ref.Collection); err != nil {
				slog.Warn("reconcile discovered dataset", "collection", ref.Collection, "err", err)
				continue
			}
			known[ref.Collection] = true
			added++
		}
	} else {
		slog.Warn("reconcile: discover datasets", "err", err)
	}
	return added
}

func (s *Server) handleOperatorsPage(w http.ResponseWriter, r *http.Request) {
	ops, err := s.operators.ListOperators(r.Context())
	if err != nil {
		http.Error(w, "failed to list operators: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "operators.html", "Operators", "operators", map[string]any{
		"Operators": ops,
		"Error":     r.URL.Query().Get("error"),
	})
}

func (s *Server) handleOperatorCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/operators?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
		return
	}
	if _, err := s.operators.CreateOperator(r.Context(), r.PostFormValue("username"), r.PostFormValue("display_name")); err != nil {
		http.Redirect(w, r, "/operators?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/operators", http.StatusSeeOther)
}

func (s *Server) handleOperatorDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.operators.DeleteOperator(r.Context(), r.PathValue("username")); err != nil {
		http.Redirect(w, r, "/operators?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/operators", http.StatusSeeOther)
}

// --- data-source catalog & self-subscribe (any authenticated user) ---

// handleCatalogPage lists every registered dataset with a subscribe/unsubscribe
// control. Subscribing is what grants the user access to view the data.
func (s *Server) handleCatalogPage(w http.ResponseWriter, r *http.Request) {
	s.reconcileDatasets(r.Context()) // ensure pilots + uploaded/live datasets are listed
	// Reflect the admin's "viewing as" persona when one is active, so previewing
	// the catalog shows the assumed user's subscriptions (read-only).
	me, preview := s.previewUser(r)
	sets, err := s.operators.ListDatasets(r.Context())
	if err != nil {
		http.Error(w, "failed to list data sources: "+err.Error(), http.StatusInternalServerError)
		return
	}
	type catItem struct {
		Key, Name, Kind, Collection, OpenPath string
		Subscribed                            bool
		Subscribers                           int
	}
	items := make([]catItem, 0, len(sets))
	subscribed := 0
	for _, d := range sets {
		open := "/datasets/" + d.Collection
		sub := d.AssignedToUser(me)
		if sub {
			subscribed++
		}
		items = append(items, catItem{
			Key: d.Key, Name: d.Name, Kind: d.Kind, Collection: d.Collection,
			OpenPath: open, Subscribed: sub, Subscribers: len(d.AssignedTo),
		})
	}
	s.render(w, r, "catalog.html", "Data sources", "catalog", map[string]any{
		"Items":      items,
		"MineCount":  subscribed,
		"TotalCount": len(items),
		"Preview":    preview, // previewing another user: show their subs, hide actions
		"Error":      r.URL.Query().Get("error"),
		"Synced":     r.URL.Query().Get("synced"),
	})
}

// handleCatalogSync runs discovery on demand: surface any dataset collections in
// the peat node (incl. mesh-synced) that aren't in the catalog yet.
func (s *Server) handleCatalogSync(w http.ResponseWriter, r *http.Request) {
	added := s.reconcileDatasets(r.Context())
	http.Redirect(w, r, "/catalog?synced="+strconv.Itoa(added), http.StatusSeeOther)
}

func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	me := s.effectiveUser(r)
	if me == "" {
		s.forbidden(w, r)
		return
	}
	if err := s.operators.Subscribe(r.Context(), r.PathValue("key"), me); err != nil {
		http.Redirect(w, r, "/catalog?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/catalog", http.StatusSeeOther)
}

func (s *Server) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	me := s.effectiveUser(r)
	if me == "" {
		s.forbidden(w, r)
		return
	}
	if err := s.operators.Unsubscribe(r.Context(), r.PathValue("key"), me); err != nil {
		http.Redirect(w, r, "/catalog?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/catalog", http.StatusSeeOther)
}

// --- combine data sources (any authenticated user) ---

// combinableDatasets returns generic datasets (uploaded / weather / HTTP) with
// their columns — the sources eligible to be joined. Pilots and existing
// combined sources are excluded (their rows aren't plain string maps / would
// nest).
func (s *Server) combinableDatasets(ctx context.Context) []map[string]any {
	sets, err := s.operators.ListDatasets(ctx)
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(sets))
	for _, d := range sets {
		if d.Kind != operators.KindGeneric {
			continue
		}
		_, cols, _, err := s.datasets.View(ctx, d.Collection)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"Collection": d.Collection, "Name": d.Name, "Columns": cols})
	}
	return out
}

// handleCombineNew renders the join builder.
func (s *Server) handleCombineNew(w http.ResponseWriter, r *http.Request) {
	if s.combine == nil {
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}
	s.reconcileDatasets(r.Context())
	sources := s.combinableDatasets(r.Context())
	cols := map[string][]string{}
	for _, d := range sources {
		cols[d["Collection"].(string)] = d["Columns"].([]string)
	}
	colsJSON, _ := json.Marshal(cols)
	s.render(w, r, "combine_new.html", "Combine data sources", "catalog", map[string]any{
		"Sources":     sources,
		"ColumnsJSON": template.JS(colsJSON),
		"Error":       r.URL.Query().Get("error"),
	})
}

// handleCombineCreate builds a combined source, registers + subscribes the
// creator, and opens it.
func (s *Server) handleCombineCreate(w http.ResponseWriter, r *http.Request) {
	if s.combine == nil {
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/combine/new?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
		return
	}
	me := s.effectiveUser(r)
	c, err := s.combine.Create(r.Context(), combineInputFromForm(r, me))
	if err != nil {
		http.Redirect(w, r, "/combine/new?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.operators.RegisterDataset(r.Context(), c.Key, c.Name, operators.KindCombined, c.Key); err != nil {
		slog.Warn("register combined source", "err", err)
	}
	if me != "" {
		_ = s.operators.Subscribe(r.Context(), c.Key, me) // creator auto-subscribes
	}
	http.Redirect(w, r, "/datasets/"+c.Key, http.StatusSeeOther)
}

// combineInputFromForm reads a combine spec from a posted form.
func combineInputFromForm(r *http.Request, owner string) combine.Input {
	return combine.Input{
		Name:        r.PostFormValue("name"),
		Owner:       owner,
		Left:        combine.Member{Collection: r.PostFormValue("left"), Key: r.PostFormValue("left_key")},
		Right:       combine.Member{Collection: r.PostFormValue("right"), Key: r.PostFormValue("right_key")},
		OnlyMatched: r.PostFormValue("only_matched") == "on",
	}
}

// combineMatchInfo renders a plain-language match summary for a join result.
func combineMatchInfo(res combine.Result) string {
	if res.Total == 0 {
		return "The first source has no rows."
	}
	if res.Matched == 0 {
		return fmt.Sprintf("⚠ 0 of %d rows matched — the key columns don't share any values. Matching ignores case and spacing; double-check you picked columns that hold the same thing.", res.Total)
	}
	if res.Unmatched == 0 {
		return fmt.Sprintf("✓ all %d rows matched.", res.Total)
	}
	return fmt.Sprintf("✓ %d of %d rows matched; %d had no match (their second-source columns are blank).", res.Matched, res.Total, res.Unmatched)
}

// handleCombinePreview computes an unsaved join and returns match stats + a
// sample of rows as JSON, powering the builder's live preview.
func (s *Server) handleCombinePreview(w http.ResponseWriter, r *http.Request) {
	if s.combine == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "combine not configured"})
		return
	}
	_ = r.ParseForm()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.combine.Preview(ctx, combineInputFromForm(r, ""))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sample := res.Rows
	if len(sample) > 8 {
		sample = sample[:8]
	}
	rows := make([][]string, 0, len(sample))
	for _, row := range sample {
		cells := make([]string, len(res.Columns))
		for i, c := range res.Columns {
			cells[i] = row.Fields[c]
		}
		rows = append(rows, cells)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"columns":   res.Columns,
		"rows":      rows,
		"matched":   res.Matched,
		"unmatched": res.Unmatched,
		"total":     res.Total,
		"info":      combineMatchInfo(res),
	})
}

// handleCombineDelete removes a combined source (and its registry entry).
func (s *Server) handleCombineDelete(w http.ResponseWriter, r *http.Request) {
	if s.combine == nil {
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}
	key := r.PathValue("key")
	if err := s.combine.Delete(r.Context(), key); err != nil {
		http.Redirect(w, r, "/catalog?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	// Also drop the catalog/registry entry (and its subscriptions); otherwise the
	// combined source keeps showing after its spec is gone.
	if err := s.operators.DeleteDataset(r.Context(), key); err != nil {
		slog.Warn("delete combined registry entry", "key", key, "err", err)
	}
	http.Redirect(w, r, "/catalog", http.StatusSeeOther)
}

// datasetDisplayLimit caps how many rows the dataset table renders at once.
const datasetDisplayLimit = 200

// --- meeting decks: publish visuals to a shared space ---

// deckPanelLimit caps table rows rendered per slide so a deck page stays light.
const deckPanelLimit = 100

// panel is a rendered visual (chart or table) for a slide's live spec.
type panel struct {
	Title, By, At   string
	SlideID, DeckID string
	Name            string
	Columns         []string
	Rows            []dataset.Row
	Total, Shown    int
	ViewType        string
	ViewGroupBy     string
	ViewValueCol    string
	ViewAgg         string
	WheelSegments   []wheelSegment
	WheelGradient   template.CSS
	Bars            []barVM
	Stats           statsVM
	Line            lineVM
	HasLine         bool
	Err             string
}

// loadDataset reads a dataset's name/columns/rows, transparently computing a
// combined source if the collection is one.
func (s *Server) loadDataset(ctx context.Context, collection string) (string, []string, []dataset.Row, error) {
	if s.combine != nil {
		if _, ok, _ := s.combine.Get(ctx, collection); ok {
			res, err := s.combine.Compute(ctx, collection)
			return res.Name, res.Columns, res.Rows, err
		}
	}
	return s.datasets.View(ctx, collection)
}

// renderSlidePanel re-computes a slide's visual from its live spec. A missing
// source yields a panel with Err set rather than failing the whole deck.
func (s *Server) renderSlidePanel(ctx context.Context, sl deck.Slide) panel {
	p := panel{
		Title: sl.Title, By: sl.PublishedBy, At: sl.PublishedAt, SlideID: sl.ID, DeckID: sl.DeckID,
		ViewType: sl.ViewType, ViewGroupBy: sl.GroupBy, ViewValueCol: sl.ValueCol, ViewAgg: firstNonEmpty(sl.Agg, "count"),
	}
	name, cols, rows, err := s.loadDataset(ctx, sl.Collection)
	if err != nil {
		p.Name = firstNonEmpty(sl.DatasetName, sl.Collection)
		p.Err = "source unavailable"
		return p
	}
	p.Name, p.Columns = name, cols
	filtered := rows
	if (sl.FilterCol != "" && sl.FilterVal != "") || sl.Query != "" {
		filtered = filtered[:0:0]
		for _, row := range rows {
			if rowMatches(row.Fields, sl.FilterCol, sl.FilterVal, sl.Query) {
				filtered = append(filtered, row)
			}
		}
	}
	p.Total = len(filtered)
	shown := filtered
	if len(shown) > deckPanelLimit {
		shown = shown[:deckPanelLimit]
	}
	p.Rows, p.Shown = shown, len(shown)
	switch p.ViewType {
	case "wheel":
		if p.ViewGroupBy != "" {
			p.WheelSegments, p.WheelGradient = computeWheel(filtered, p.ViewGroupBy)
		}
	case "bar":
		p.Bars = computeBars(filtered, p.ViewGroupBy, p.ViewValueCol, p.ViewAgg)
	case "line":
		p.Line, p.HasLine = computeLine(filtered, p.ViewGroupBy, p.ViewValueCol, p.ViewAgg)
	case "stats":
		p.Stats = computeStats(filtered, p.ViewValueCol)
	}
	return p
}

// handleDecksPage lists all decks (any authenticated user) with a create form.
func (s *Server) handleDecksPage(w http.ResponseWriter, r *http.Request) {
	if s.deck == nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	decks, err := s.deck.ListDecks(r.Context())
	if err != nil {
		http.Error(w, "failed to list decks: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "decks.html", "Decks", "decks", map[string]any{
		"Decks": decks,
		"Error": r.URL.Query().Get("error"),
	})
}

func (s *Server) handleDeckCreate(w http.ResponseWriter, r *http.Request) {
	if s.deck == nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	d, err := s.deck.CreateDeck(r.Context(), r.PostFormValue("name"), s.effectiveUser(r))
	if err != nil {
		http.Redirect(w, r, "/decks?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/decks/"+d.ID, http.StatusSeeOther)
}

// handleDeckView renders a deck: every slide re-rendered from its live spec.
func (s *Server) handleDeckView(w http.ResponseWriter, r *http.Request) {
	if s.deck == nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	d, ok, err := s.deck.GetDeck(r.Context(), id)
	if err != nil || !ok {
		http.Error(w, "deck not found", http.StatusNotFound)
		return
	}
	slides, _ := s.deck.Slides(r.Context(), id)
	panels := make([]panel, 0, len(slides))
	for _, sl := range slides {
		panels = append(panels, s.renderSlidePanel(r.Context(), sl))
	}
	s.render(w, r, "deck.html", d.Name, "decks", map[string]any{
		"Deck":   d,
		"Panels": panels,
		"Error":  r.URL.Query().Get("error"),
	})
}

func (s *Server) handleDeckDelete(w http.ResponseWriter, r *http.Request) {
	if s.deck != nil {
		if err := s.deck.DeleteDeck(r.Context(), r.PathValue("id")); err != nil {
			http.Redirect(w, r, "/decks?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/decks", http.StatusSeeOther)
}

func (s *Server) handleSlideDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.deck != nil {
		_ = s.deck.DeleteSlide(r.Context(), r.PathValue("sid"))
	}
	http.Redirect(w, r, "/decks/"+id, http.StatusSeeOther)
}

// handlePublish publishes the current dataset view (filter + visualization) as a
// slide on an existing deck, or a new deck if a name is given.
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	collection := r.PathValue("collection")
	if !s.canAccessDataset(r, collection) {
		s.forbidden(w, r)
		return
	}
	if s.deck == nil {
		http.Redirect(w, r, "/datasets/"+collection, http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	back := "/datasets/" + collection
	if bq := r.PostFormValue("back"); bq != "" {
		back = "/datasets/" + collection + "?" + bq
	}
	fail := func(msg string) { http.Redirect(w, r, back+"&error="+url.QueryEscape(msg), http.StatusSeeOther) }

	deckID := r.PostFormValue("deck")
	if newName := strings.TrimSpace(r.PostFormValue("new_deck")); newName != "" {
		d, err := s.deck.CreateDeck(r.Context(), newName, s.effectiveUser(r))
		if err != nil {
			fail(err.Error())
			return
		}
		deckID = d.ID
	}
	if deckID == "" {
		fail("choose a deck or name a new one")
		return
	}
	name, _, _, _ := s.loadDataset(r.Context(), collection)
	_, err := s.deck.AddSlide(r.Context(), deck.Slide{
		DeckID:      deckID,
		Title:       r.PostFormValue("title"),
		Collection:  collection,
		DatasetName: name,
		FilterCol:   r.PostFormValue("col"),
		FilterVal:   r.PostFormValue("val"),
		Query:       r.PostFormValue("q"),
		ViewType:    r.PostFormValue("vtype"),
		GroupBy:     r.PostFormValue("vgroup"),
		ValueCol:    r.PostFormValue("vval"),
		Agg:         r.PostFormValue("vagg"),
		PublishedBy: s.effectiveUser(r),
	})
	if err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/decks/"+deckID, http.StatusSeeOther)
}

// --- helpers ---

// render wraps a page's content template in the shared layout. name is the
// page's content block; title and nav set the document title and active nav
// item. The page's data map is augmented with shell fields (Username, IsAdmin)
// pulled from the request so every page gets a consistent header.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Content"] = name
	data["Title"] = title
	data["Nav"] = nav
	if _, ok := data["Username"]; !ok {
		if claims, ok := auth.ClaimsFromContext(r.Context()); ok && claims != nil {
			data["Username"] = firstNonEmpty(claims.PreferredUsername, claims.Name, claims.Subject)
		}
	}
	if _, ok := data["IsAdmin"]; !ok {
		claims, _ := auth.ClaimsFromContext(r.Context())
		data["IsAdmin"] = s.auth.IsAdmin(claims)
	}
	// Global "viewing as" banner so the persona is visible (and exitable) on
	// every page, not just the dashboard.
	if persona, active := s.previewUser(r); active {
		data["Persona"] = persona
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
