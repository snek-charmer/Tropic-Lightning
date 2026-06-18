package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/defenseunicorns/keycloak-portal/internal/config"
)

// Authenticator wraps the OIDC provider, the OAuth2 client configuration, and
// the verifiers used to validate tokens coming back from Keycloak.
type Authenticator struct {
	provider *oidc.Provider
	oauth2   oauth2.Config

	// idTokenVerifier validates ID tokens, checking that the audience matches
	// our client ID (standard OIDC behaviour).
	idTokenVerifier *oidc.IDTokenVerifier

	// accessTokenVerifier validates Keycloak access tokens. Keycloak access
	// tokens are JWTs whose audience is often "account" rather than this client,
	// so we skip the client-ID/audience check and rely on signature, issuer, and
	// expiry. Roles live in the access token's realm_access / resource_access.
	accessTokenVerifier *oidc.IDTokenVerifier

	endSessionEndpoint    string
	postLogoutRedirectURL string

	// adminGroup is a Keycloak group whose members are treated as admins, in
	// addition to holders of the "admin" realm role. Empty disables group admin.
	adminGroup string

	// cookieSecure mirrors config.CookieSecure so refreshed session cookies are
	// written with the same attributes as the login flow.
	cookieSecure bool
}

// providerClaims captures the optional end_session_endpoint advertised in the
// OIDC discovery document, used to support RP-initiated logout.
type providerClaims struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

// NewAuthenticator builds the verifiers and OAuth2 client used by the rest of
// the app. With KeycloakInternalURL set, back-channel calls (token exchange,
// JWKS) target the in-cluster Keycloak while the browser uses the public issuer
// and tokens are still validated against it; otherwise it performs standard OIDC
// discovery against the issuer.
func NewAuthenticator(ctx context.Context, cfg *config.Config) (*Authenticator, error) {
	a := &Authenticator{
		postLogoutRedirectURL: cfg.PostLogoutRedirectURL,
		adminGroup:            cfg.AdminGroup,
		cookieSecure:          cfg.CookieSecure,
	}

	if cfg.KeycloakInternalURL != "" {
		return newInternalBackchannelAuthenticator(ctx, cfg, a)
	}

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for issuer %q: %w", cfg.Issuer, err)
	}
	var pc providerClaims
	if err := provider.Claims(&pc); err != nil {
		return nil, fmt.Errorf("parsing provider metadata: %w", err)
	}

	a.provider = provider
	a.oauth2 = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	a.idTokenVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	a.accessTokenVerifier = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	a.endSessionEndpoint = pc.EndSessionEndpoint
	return a, nil
}

// newInternalBackchannelAuthenticator wires endpoints by hand: the browser-facing
// authorize/logout URLs use the public issuer, while token exchange and JWKS use
// the in-cluster Keycloak (cfg.KeycloakInternalURL). Tokens are validated against
// the public issuer (their "iss" claim). Discovery is skipped so the public host
// is never reached from the pod.
func newInternalBackchannelAuthenticator(ctx context.Context, cfg *config.Config, a *Authenticator) (*Authenticator, error) {
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer %q: %w", cfg.Issuer, err)
	}
	realmPath := strings.TrimRight(issuerURL.Path, "/") // e.g. /realms/uds
	publicBase := strings.TrimRight(cfg.Issuer, "/")
	internalBase := strings.TrimRight(cfg.KeycloakInternalURL, "/") + realmPath

	a.oauth2 = oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  publicBase + "/protocol/openid-connect/auth",    // browser (front-channel)
			TokenURL: internalBase + "/protocol/openid-connect/token", // pod (back-channel)
		},
	}

	// Verify against the public issuer, but fetch keys from the in-cluster JWKS.
	keySet := oidc.NewRemoteKeySet(ctx, internalBase+"/protocol/openid-connect/certs")
	a.idTokenVerifier = oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{ClientID: cfg.ClientID})
	a.accessTokenVerifier = oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{SkipClientIDCheck: true})
	a.endSessionEndpoint = publicBase + "/protocol/openid-connect/logout"
	return a, nil
}

// AuthCodeURL builds the URL to redirect the browser to in order to start the
// authorization code flow. The nonce binds the resulting ID token to this login.
func (a *Authenticator) AuthCodeURL(state, nonce string) string {
	return a.oauth2.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange trades an authorization code for a token set.
func (a *Authenticator) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return a.oauth2.Exchange(ctx, code)
}

// Refresh exchanges a refresh token for a new token set (silent re-auth). The
// back-channel token endpoint is used (in-cluster when configured).
func (a *Authenticator) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return a.oauth2.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// VerifyIDToken validates the raw ID token's signature, issuer, audience, and
// expiry, returning the parsed token.
func (a *Authenticator) VerifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return a.idTokenVerifier.Verify(ctx, rawIDToken)
}

// VerifyAccessToken validates a Keycloak access token (a JWT) and returns the
// claims, including the realm and client roles. This is the verification path
// used by the bearer-token middleware on every protected request.
func (a *Authenticator) VerifyAccessToken(ctx context.Context, rawToken string) (*Claims, error) {
	tok, err := a.accessTokenVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verifying access token: %w", err)
	}
	var claims Claims
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing access token claims: %w", err)
	}
	return &claims, nil
}

// LogoutURL returns the Keycloak RP-initiated logout URL. The ID token hint lets
// Keycloak end the SSO session without an extra confirmation prompt. If the
// provider did not advertise an end_session_endpoint, the post-logout redirect
// is returned so the caller can still bounce the browser somewhere sensible.
func (a *Authenticator) LogoutURL(idTokenHint string) string {
	if a.endSessionEndpoint == "" {
		return a.postLogoutRedirectURL
	}
	u := a.endSessionEndpoint + "?post_logout_redirect_uri=" + urlQueryEscape(a.postLogoutRedirectURL)
	if idTokenHint != "" {
		u += "&id_token_hint=" + urlQueryEscape(idTokenHint)
	}
	return u
}
