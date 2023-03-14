// Package hsdp implements logging in through OpenID Connect providers.
// HSDP IAM is almost but not quite compatible with OIDC standards, hence this connector.
package hsdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds configuration options for OpenID Connect logins.
type Config struct {
	Issuer         string `json:"issuer"`
	InsecureIssuer string `json:"insecureIssuer"`
	ClientID       string `json:"clientID"`
	ClientSecret   string `json:"clientSecret"`
	RedirectURI    string `json:"redirectURI"`
	TrustedOrgID   string `json:"trustedOrgID"`
	SAML2LoginURL  string `json:"saml2LoginURL"`

	// Extensions implemented by HSP IAM
	Extension

	// Causes client_secret to be passed as POST parameters instead of basic
	// auth. This is specifically "NOT RECOMMENDED" by the OAuth2 RFC, but some
	// providers require it.
	//
	// https://tools.ietf.org/html/rfc6749#section-2.3.1
	BasicAuthUnsupported *bool `json:"basicAuthUnsupported"`

	Scopes []string `json:"scopes"` // defaults to "profile" and "email"

	// Optional list of whitelisted domains when using Google
	// If this field is nonempty, only users from a listed domain will be allowed to log in
	HostedDomains []string `json:"hostedDomains"`

	// Override the value of email_verifed to true in the returned claims
	InsecureSkipEmailVerified bool `json:"insecureSkipEmailVerified"`

	// InsecureEnableGroups enables groups claims. This is disabled by default until https://github.com/dexidp/dex/issues/1065 is resolved
	InsecureEnableGroups bool `json:"insecureEnableGroups"`

	// GetUserInfo uses the userinfo endpoint to get additional claims for
	// the token. This is especially useful where upstreams return "thin"
	// id tokens
	GetUserInfo bool `json:"getUserInfo"`

	// Configurable key which contains the user id claim
	UserIDKey string `json:"userIDKey"`

	// Configurable key which contains the user name claim
	UserNameKey string `json:"userNameKey"`

	// PromptType will be used fot the prompt parameter (when offline_access, by default prompt=consent)
	PromptType string `json:"promptType"`
}

type Extension struct {
	IntrosepctionEndpoint string `json:"introspection_endpoint"`
}

// connectorData stores information for sessions authenticated by this connector
type connectorData struct {
	RefreshToken []byte
}

// Open returns a connector which can be used to login users through an upstream
// OpenID Connect provider.
func (c *Config) Open(id string, logger log.Logger) (conn connector.Connector, err error) {
	parentContext, cancel := context.WithCancel(context.Background())

	ctx := oidc.InsecureIssuerURLContext(parentContext, c.InsecureIssuer)

	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	endpoint := provider.Endpoint()

	// HSP IAM extension
	if err := provider.Claims(&c.Extension); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get introspection endpoint: %v", err)
	}

	if c.BasicAuthUnsupported != nil {
		// Setting "basicAuthUnsupported" always overrides our detection.
		if *c.BasicAuthUnsupported {
			endpoint.AuthStyle = oauth2.AuthStyleInParams
		}
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(c.Scopes) > 0 {
		scopes = append(scopes, c.Scopes...)
	} else {
		scopes = append(scopes, "profile", "email", "groups")
	}

	// PromptType should be "consent" by default, if not set
	if c.PromptType == "" {
		c.PromptType = "consent"
	}

	clientID := c.ClientID
	return &hsdpConnector{
		provider:      provider,
		redirectURI:   c.RedirectURI,
		introspectURI: c.IntrosepctionEndpoint,
		trustedOrgID:  c.TrustedOrgID,
		samlLoginURL:  c.SAML2LoginURL,
		clientID:      c.ClientID,
		clientSecret:  c.ClientSecret,
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     endpoint,
			Scopes:       scopes,
			RedirectURL:  c.RedirectURI,
		},
		verifier: provider.Verifier(
			&oidc.Config{
				ClientID:        clientID,
				SkipIssuerCheck: true, // Horribly broken currently
			},
		),
		logger:                    logger,
		cancel:                    cancel,
		hostedDomains:             c.HostedDomains,
		insecureSkipEmailVerified: c.InsecureSkipEmailVerified,
		insecureEnableGroups:      c.InsecureEnableGroups,
		getUserInfo:               c.GetUserInfo,
		userIDKey:                 c.UserIDKey,
		userNameKey:               c.UserNameKey,
		promptType:                c.PromptType,
	}, nil
}

var (
	_ connector.CallbackConnector = (*hsdpConnector)(nil)
	_ connector.RefreshConnector  = (*hsdpConnector)(nil)
)

type tokenResponse struct {
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

type hsdpConnector struct {
	provider                  *oidc.Provider
	redirectURI               string
	introspectURI             string
	trustedOrgID              string
	samlLoginURL              string
	clientID                  string
	clientSecret              string
	oauth2Config              *oauth2.Config
	verifier                  *oidc.IDTokenVerifier
	cancel                    context.CancelFunc
	logger                    log.Logger
	hostedDomains             []string
	insecureSkipEmailVerified bool
	insecureEnableGroups      bool
	getUserInfo               bool
	userIDKey                 string
	userNameKey               string
	promptType                string
}

func (c *hsdpConnector) isSAML() bool {
	return len(c.samlLoginURL) > 0
}

func (c *hsdpConnector) Close() error {
	c.cancel()
	return nil
}

func (c *hsdpConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	// SAML2 flow
	if c.isSAML() {
		cbu, _ := url.Parse(callbackURL)
		values := cbu.Query()
		values.Set("state", state)
		cbu.RawQuery = values.Encode()

		u, err := url.Parse(c.samlLoginURL)
		if err != nil {
			return "", fmt.Errorf("invalid SAML2 login URL: %w", err)
		}
		values = u.Query()
		values.Set("redirect_uri", cbu.String())
		u.RawQuery = values.Encode()
		return u.String(), nil
	}

	var opts []oauth2.AuthCodeOption
	if len(c.hostedDomains) > 0 {
		preferredDomain := c.hostedDomains[0]
		if len(c.hostedDomains) > 1 {
			preferredDomain = "*"
		}
		opts = append(opts, oauth2.SetAuthURLParam("hd", preferredDomain))
	}

	if s.OfflineAccess {
		opts = append(opts, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", c.promptType))
	}
	return c.oauth2Config.AuthCodeURL(state, opts...), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

func (c *hsdpConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	// SAML2 flow
	if c.isSAML() {
		assertion := q.Get("assertion")
		form := url.Values{}
		form.Add("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer")
		form.Add("assertion", assertion)
		requestBody := form.Encode()
		req, _ := http.NewRequest(http.MethodPost, c.oauth2Config.Endpoint.TokenURL, io.NopCloser(strings.NewReader(requestBody)))
		req.SetBasicAuth(c.clientID, c.clientSecret)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Api-Version", "2")
		req.ContentLength = int64(len(requestBody))

		resp, err := doRequest(r.Context(), req)
		if err != nil {
			return identity, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return identity, err
		}
		if resp.StatusCode != http.StatusOK {
			return identity, fmt.Errorf("%s: %s", resp.Status, body)
		}

		var tr tokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return identity, fmt.Errorf("hsdp: failed to token response: %v", err)
		}
		token := &oauth2.Token{
			AccessToken:  tr.AccessToken,
			TokenType:    tr.TokenType,
			RefreshToken: tr.RefreshToken,
			Expiry:       time.Unix(tr.ExpiresIn, 0),
		}
		return c.createIdentity(r.Context(), identity, token)
	}

	token, err := c.oauth2Config.Exchange(r.Context(), q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get token: %v", err)
	}

	return c.createIdentity(r.Context(), identity, token)
}

// Refresh is used to refresh a session with the refresh token provided by the IdP
func (c *hsdpConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	cd := connectorData{}
	err := json.Unmarshal(identity.ConnectorData, &cd)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to unmarshal connector data: %v", err)
	}

	t := &oauth2.Token{
		RefreshToken: string(cd.RefreshToken),
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.oauth2Config.TokenSource(ctx, t).Token()
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to get refresh token: %v", err)
	}

	return c.createIdentity(ctx, identity, token)
}

func (c *hsdpConnector) createIdentity(ctx context.Context, identity connector.Identity, token *oauth2.Token) (connector.Identity, error) {
	var claims map[string]interface{}

	if !c.isSAML() {
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			return identity, errors.New("oidc: no id_token in token response")
		}
		idToken, err := c.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return identity, fmt.Errorf("oidc: failed to verify ID Token: %v", err)
		}
		if err := idToken.Claims(&claims); err != nil {
			return identity, fmt.Errorf("oidc: failed to decode claims: %v", err)
		}
	}

	// We immediately want to run getUserInfo if configured before we validate the claims
	if c.getUserInfo {
		userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return identity, fmt.Errorf("oidc: error loading userinfo: %v", err)
		}
		if err := userInfo.Claims(&claims); err != nil {
			return identity, fmt.Errorf("oidc: failed to decode userinfo claims: %v", err)
		}
	}

	// Introspect so we can get group assignments
	introspectResponse, err := c.introspect(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return identity, fmt.Errorf("hsdp: introspect failed: %w", err)
	}

	userNameKey := "name"
	if c.userNameKey != "" {
		userNameKey = c.userNameKey
	}
	name, found := claims[userNameKey].(string)
	if !found {
		return identity, fmt.Errorf("missing \"%s\" claim", userNameKey)
	}

	hasEmailScope := false
	for _, s := range c.oauth2Config.Scopes {
		if s == "email" {
			hasEmailScope = true
			break
		}
	}

	email, found := claims["email"].(string)
	if !found && hasEmailScope {
		return identity, errors.New("missing \"email\" claim")
	}

	emailVerified, found := claims["email_verified"].(bool)
	if !found && !c.isSAML() {
		if c.insecureSkipEmailVerified {
			emailVerified = true
		} else if hasEmailScope {
			return identity, errors.New("missing \"email_verified\" claim")
		}
	}
	if c.isSAML() { // For SAML2 we claim email verification for now
		emailVerified = true
	}
	hostedDomain, _ := claims["hd"].(string)

	if len(c.hostedDomains) > 0 {
		found := false
		for _, domain := range c.hostedDomains {
			if hostedDomain == domain {
				found = true
				break
			}
		}
		if !found {
			return identity, fmt.Errorf("oidc: unexpected hd claim %v", hostedDomain)
		}
	}

	cd := connectorData{
		RefreshToken: []byte(token.RefreshToken),
	}

	connData, err := json.Marshal(&cd)
	if err != nil {
		return identity, fmt.Errorf("oidc: failed to encode connector data: %v", err)
	}

	identity = connector.Identity{
		UserID:        introspectResponse.Sub,
		Username:      name,
		Email:         email,
		EmailVerified: emailVerified,
		ConnectorData: connData,
	}

	if c.userIDKey != "" {
		userID, found := claims[c.userIDKey].(string)
		if !found {
			return identity, fmt.Errorf("oidc: not found %v claim", c.userIDKey)
		}
		identity.UserID = userID
	}

	if c.insecureEnableGroups {
		vs, ok := claims["groups"].([]interface{})
		if ok {
			for _, v := range vs {
				if s, ok := v.(string); ok {
					identity.Groups = append(identity.Groups, s)
				} else {
					return identity, errors.New("malformed \"groups\" claim")
				}
			}
		}
	}

	// HSP IAM groups from trustedOrgID
	for _, org := range introspectResponse.Organizations.OrganizationList {
		if org.OrganizationID == c.trustedOrgID { // Add groups from managing ORG
			identity.Groups = append(identity.Groups, org.Groups...)
		}
	}

	return identity, nil
}
