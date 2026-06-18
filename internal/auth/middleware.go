package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AccessTokenCookie is the cookie used to carry the access token for browser
// navigation of the server-rendered portal. Programmatic/API callers may
// instead send the token in the Authorization header.
const AccessTokenCookie = "access_token"

// RefreshTokenCookie carries the OIDC refresh token so the session can be
// silently renewed when the (short-lived) access token expires, instead of
// bouncing the user through login.
const RefreshTokenCookie = "refresh_token"

// refreshCookieTTL is how long the refresh-token cookie persists. The server may
// reject the refresh sooner (its own lifetime); we then fall back to login.
const refreshCookieTTL = 12 * time.Hour

type contextKey string

const claimsContextKey contextKey = "auth.claims"

// Claims is the subset of Keycloak token claims the application cares about.
// Realm roles live under realm_access.roles; per-client roles live under
// resource_access.<clientID>.roles.
type Claims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`

	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`

	// Groups holds Keycloak group memberships (from a group-membership protocol
	// mapper). With full-path mapping these look like "/UDS Core/Admin".
	Groups []string `json:"groups"`
}

// HasRealmRole reports whether the user holds the given realm-level role.
func (c *Claims) HasRealmRole(role string) bool {
	return contains(c.RealmAccess.Roles, role)
}

// HasGroup reports whether the user is a member of the given Keycloak group.
func (c *Claims) HasGroup(group string) bool {
	return contains(c.Groups, group)
}

// AllGroups returns the user's group memberships (handy for templates/JSON).
func (c *Claims) AllGroups() []string {
	return c.Groups
}

// HasClientRole reports whether the user holds the given role on a specific
// Keycloak client.
func (c *Claims) HasClientRole(client, role string) bool {
	ra, ok := c.ResourceAccess[client]
	if !ok {
		return false
	}
	return contains(ra.Roles, role)
}

// AllRealmRoles returns the user's realm roles (handy for templates/JSON).
func (c *Claims) AllRealmRoles() []string {
	return c.RealmAccess.Roles
}

// Authenticate verifies the bearer token (from the Authorization header or the
// session cookie), stashes the resulting claims in the request context, and
// calls the next handler. Unauthenticated browser requests are redirected to
// login; API requests receive 401.
func (a *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := a.verifyOrRefresh(w, r)
		if claims == nil {
			a.deny(w, r, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// verifyOrRefresh validates the access token; if it is missing/expired, it tries
// a silent refresh using the refresh-token cookie (browser sessions). On a
// successful refresh it rewrites the session cookies so subsequent requests use
// the new token. Returns nil when neither path authenticates the request.
func (a *Authenticator) verifyOrRefresh(w http.ResponseWriter, r *http.Request) *Claims {
	if raw := extractToken(r); raw != "" {
		if claims, err := a.VerifyAccessToken(r.Context(), raw); err == nil {
			return claims
		}
	}

	rt, err := r.Cookie(RefreshTokenCookie)
	if err != nil || rt.Value == "" {
		return nil
	}
	tok, err := a.Refresh(r.Context(), rt.Value)
	if err != nil {
		return nil
	}
	claims, err := a.VerifyAccessToken(r.Context(), tok.AccessToken)
	if err != nil {
		return nil
	}

	// Persist the renewed session for subsequent browser navigation.
	ttl := time.Until(tok.Expiry)
	if ttl <= 0 {
		ttl = time.Hour
	}
	a.writeSessionCookie(w, AccessTokenCookie, tok.AccessToken, ttl)
	if tok.RefreshToken != "" {
		a.writeSessionCookie(w, RefreshTokenCookie, tok.RefreshToken, refreshCookieTTL)
	}
	return claims
}

// writeSessionCookie sets a session cookie with the same attributes the login
// flow uses.
func (a *Authenticator) writeSessionCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
	})
}

// RequireRealmRole guards a handler so that only users holding the given
// realm-level role may proceed. It must run inside Authenticate.
func (a *Authenticator) RequireRealmRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !claims.HasRealmRole(role) {
				a.deny(w, r, http.StatusForbidden, "missing required realm role: "+role)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IsAdmin reports whether the claims grant admin: either the "admin" realm role
// or membership in the configured admin group (e.g. "/UDS Core/Admin").
func (a *Authenticator) IsAdmin(c *Claims) bool {
	if c == nil {
		return false
	}
	if c.HasRealmRole("admin") {
		return true
	}
	return a.adminGroup != "" && c.HasGroup(a.adminGroup)
}

// RequireAdmin guards a handler so only admins (admin realm role OR admin group)
// may proceed. It must run inside Authenticate.
func (a *Authenticator) RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !a.IsAdmin(claims) {
				a.deny(w, r, http.StatusForbidden, "admin access required (admin realm role or group)")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireClientRole guards a handler by a role on a specific Keycloak client.
func (a *Authenticator) RequireClientRole(client, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || !claims.HasClientRole(client, role) {
				a.deny(w, r, http.StatusForbidden, "missing required client role: "+client+":"+role)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClaimsFromContext retrieves the verified claims placed by Authenticate.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsContextKey).(*Claims)
	return c, ok
}

// extractToken pulls the access token from the Authorization header first
// (programmatic callers), falling back to the session cookie (browser
// navigation of the portal).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	if c, err := r.Cookie(AccessTokenCookie); err == nil {
		return c.Value
	}
	return ""
}

// deny renders an auth failure. Browser (HTML) requests are redirected to the
// login flow; everything else gets a JSON error with the right status code.
func (a *Authenticator) deny(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if status == http.StatusUnauthorized && acceptsHTML(r) {
		dest := "/auth/login"
		if rt := returnTarget(r); rt != "" {
			dest += "?return_to=" + url.QueryEscape(rt)
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// returnTarget computes a safe local path to send the user back to after login:
// the current URL for GET navigation, or the Referer for other methods.
func returnTarget(r *http.Request) string {
	cand := ""
	if r.Method == http.MethodGet {
		cand = r.URL.RequestURI()
	} else if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			cand = u.RequestURI()
		}
	}
	return SafeLocalPath(cand)
}

// SafeLocalPath returns p if it is a safe same-site path (guards against open
// redirects and auth-flow loops), else "".
func SafeLocalPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return ""
	}
	if p == "/auth" || strings.HasPrefix(p, "/auth/") {
		return ""
	}
	return p
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// urlQueryEscape is a tiny indirection so oidc.go can escape logout params
// without importing net/url directly.
func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
