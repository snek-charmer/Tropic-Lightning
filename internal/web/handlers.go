package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/defenseunicorns/keycloak-portal/internal/auth"
	"github.com/defenseunicorns/keycloak-portal/internal/config"
	"github.com/defenseunicorns/keycloak-portal/internal/datasource"
	"github.com/defenseunicorns/keycloak-portal/internal/pilots"
)

//go:embed templates/*.html
var templateFS embed.FS

const (
	stateCookie   = "oidc_state"
	nonceCookie   = "oidc_nonce"
	idTokenCookie = "id_token" // kept only as a logout hint
)

// Server holds the dependencies shared by the HTTP handlers.
type Server struct {
	auth        *auth.Authenticator
	cfg         *config.Config
	templates   *template.Template
	dataSources *datasource.Service
	pilots      *pilots.Service
}

// NewServer parses templates and returns a Server ready to register routes.
func NewServer(authn *auth.Authenticator, cfg *config.Config, ds *datasource.Service, pl *pilots.Service) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{auth: authn, cfg: cfg, templates: tmpl, dataSources: ds, pilots: pl}, nil
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
	// admin guard.
	admin := func(h http.HandlerFunc) http.Handler {
		return s.auth.Authenticate(adminOnly(h))
	}
	mux.Handle("GET /datasources", admin(s.handleDataSourcesPage))
	mux.Handle("POST /datasources", admin(s.handleDataSourceCreateForm))
	mux.Handle("POST /datasources/{id}/delete", admin(s.handleDataSourceDeleteForm))

	mux.Handle("GET /api/datasources", admin(s.handleDataSourcesList))
	mux.Handle("POST /api/datasources", admin(s.handleDataSourceCreate))
	mux.Handle("DELETE /api/datasources/{id}", admin(s.handleDataSourceDelete))

	// Pilots dataset (admin-only): view + import into peat.
	mux.Handle("GET /pilots", admin(s.handlePilotsPage))
	mux.Handle("POST /pilots/import", admin(s.handlePilotsImport))
	mux.Handle("GET /api/pilots", admin(s.handlePilotsList))

	// Operator (any authenticated user): mission readiness view + edit a pilot's
	// availability.
	authed := func(h http.HandlerFunc) http.Handler { return s.auth.Authenticate(h) }
	mux.Handle("GET /missions", authed(s.handleMissions))
	mux.Handle("POST /pilots/{id}/status", authed(s.handlePilotStatus))
	mux.Handle("GET /api/missions/summary", authed(s.handleMissionsSummary))

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
	s.render(w, "home.html", map[string]any{"Authenticated": authenticated})
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
	s.clearCookie(w, stateCookie)
	s.clearCookie(w, nonceCookie)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleLogout clears local cookies and redirects to Keycloak's RP-initiated
// logout endpoint so the SSO session is ended too.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idHint string
	if c, err := r.Cookie(idTokenCookie); err == nil {
		idHint = c.Value
	}
	s.clearCookie(w, auth.AccessTokenCookie)
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

	// Persona view: admins can preview the operator (s1) view via ?view=operator.
	isAdmin := s.auth.IsAdmin(claims)
	view := "operator"
	if isAdmin {
		view = "admin"
		if r.URL.Query().Get("view") == "operator" {
			view = "operator"
		}
	}

	s.render(w, "dashboard.html", map[string]any{
		"Username":      firstNonEmpty(claims.PreferredUsername, claims.Name, claims.Subject),
		"Email":         claims.Email,
		"RealmRoles":    claims.AllRealmRoles(),
		"Groups":        claims.AllGroups(),
		"ClientRoles":   clientRoles,
		"IsAdmin":       isAdmin,
		"View":          view, // "admin" | "operator"
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
	s.render(w, "datasources.html", map[string]any{
		"Sources":       sources,
		"KnownTypes":    datasource.KnownTypes,
		"Error":         r.URL.Query().Get("error"),
		"Created":       r.URL.Query().Get("ok") == "created",
		"Mesh":          status,
		"MeshReachable": statusErr == nil,
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

// --- pilots dataset (admin only) ---

// pilotsDisplayLimit caps how many rows the HTML table renders (the full set is
// still ingested and available via /api/pilots).
const pilotsDisplayLimit = 200

// handlePilotsPage shows the imported pilots with an Import button and mesh status.
func (s *Server) handlePilotsPage(w http.ResponseWriter, r *http.Request) {
	all, err := s.pilots.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list pilots: "+err.Error(), http.StatusInternalServerError)
		return
	}
	shown := all
	if len(shown) > pilotsDisplayLimit {
		shown = shown[:pilotsDisplayLimit]
	}
	_, connected := s.peatStatus(r.Context())
	s.render(w, "pilots.html", map[string]any{
		"Pilots":        shown,
		"Total":         len(all),
		"Shown":         len(shown),
		"Limit":         pilotsDisplayLimit,
		"Imported":      r.URL.Query().Get("imported"),
		"Error":         r.URL.Query().Get("error"),
		"PeatConnected": connected,
	})
}

// handlePilotsImport ingests the embedded dataset into peat, then redirects back.
func (s *Server) handlePilotsImport(w http.ResponseWriter, r *http.Request) {
	// Bound the bulk write so a slow/unreachable node doesn't hang the request.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	n, err := s.pilots.Import(ctx)
	if err != nil {
		http.Redirect(w, r, "/pilots?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/pilots?imported="+strconv.Itoa(n), http.StatusSeeOther)
}

// handlePilotsList is the JSON API listing of ingested pilots.
func (s *Server) handlePilotsList(w http.ResponseWriter, r *http.Request) {
	all, err := s.pilots.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if all == nil {
		all = []pilots.Pilot{}
	}
	writeJSON(w, http.StatusOK, all)
}

// --- mission readiness (operator: any authenticated user) ---

// handleMissions renders the operator view: a readiness status wheel plus an
// editable pilot list (mark grounded/available).
func (s *Server) handleMissions(w http.ResponseWriter, r *http.Request) {
	summary, err := s.pilots.ReadinessSummary(r.Context())
	if err != nil {
		http.Error(w, "failed to summarize: "+err.Error(), http.StatusInternalServerError)
		return
	}
	all, err := s.pilots.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list pilots: "+err.Error(), http.StatusInternalServerError)
		return
	}
	shown := all
	if len(shown) > pilotsDisplayLimit {
		shown = shown[:pilotsDisplayLimit]
	}
	s.render(w, "missions.html", map[string]any{
		"Summary":  summary,
		"AvailPct": summary.AvailablePct(),
		"Pilots":   shown,
		"Shown":    len(shown),
		"Updated":  r.URL.Query().Get("updated"),
		"Error":    r.URL.Query().Get("error"),
	})
}

// handlePilotStatus is the operator edit: set a pilot's mission availability.
func (s *Server) handlePilotStatus(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFromContext(r.Context())
	by := ""
	if claims != nil {
		by = firstNonEmpty(claims.PreferredUsername, claims.Name, claims.Subject)
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/missions?error="+url.QueryEscape("invalid form"), http.StatusSeeOther)
		return
	}
	id := r.PathValue("id")
	status := r.PostFormValue("status")
	note := r.PostFormValue("note")
	p, err := s.pilots.SetStatus(r.Context(), id, status, note, by)
	if err != nil {
		http.Redirect(w, r, "/missions?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/missions?updated="+url.QueryEscape(p.PilotID), http.StatusSeeOther)
}

// handleMissionsSummary returns the readiness rollup as JSON (for the wheel).
func (s *Server) handleMissionsSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.pilots.ReadinessSummary(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// --- helpers ---

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
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
