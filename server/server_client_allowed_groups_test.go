package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

// The mock callback connector this test server serves always returns an
// identity with Groups: []string{"authors"} (see connector/mock/connectortest.go).

func TestClientAllowedGroups_CallbackAllow(t *testing.T) {
	ctx := t.Context()
	connID := "mock"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)

	httpServer, s := newTestServer(t, func(c *Config) { c.Now = time.Now })
	defer httpServer.Close()

	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:            "client-allow",
		RedirectURIs:  []string{"cb"},
		AllowedGroups: []string{"authors"},
	}))
	require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
		ID:            authReqID,
		ClientID:      "client-allow",
		ConnectorID:   connID,
		RedirectURI:   "cb",
		Expiry:        expiry,
		ResponseTypes: []string{oauth2.ResponseTypeCode},
	}))

	rr := httptest.NewRecorder()
	path := fmt.Sprintf("/callback/%s?state=%s", connID, authReqID)
	s.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	require.Equal(t, 303, rr.Code)

	_, restPath := followFlow(t, s, rr)
	require.Equal(t, "/cb", restPath, "user in allowed group should complete SSO")
}

func TestClientAllowedGroups_CallbackDeny(t *testing.T) {
	ctx := t.Context()
	connID := "mock"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)

	httpServer, s := newTestServer(t, func(c *Config) { c.Now = time.Now })
	defer httpServer.Close()

	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:            "client-deny",
		RedirectURIs:  []string{"cb"},
		AllowedGroups: []string{"not-authors"},
	}))
	require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
		ID:            authReqID,
		ClientID:      "client-deny",
		ConnectorID:   connID,
		RedirectURI:   "cb",
		Expiry:        expiry,
		ResponseTypes: []string{oauth2.ResponseTypeCode},
	}))

	rr := httptest.NewRecorder()
	path := fmt.Sprintf("/callback/%s?state=%s", connID, authReqID)
	s.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	require.Equal(t, http.StatusForbidden, rr.Code, "user not in any allowed group must be rejected")

	updated, err := s.storage.GetAuthRequest(ctx, authReqID)
	require.NoError(t, err)
	require.False(t, updated.LoggedIn, "rejected login must not be marked logged in")
}

func TestClientAllowedGroups_NoRestrictionAllowsLogin(t *testing.T) {
	ctx := t.Context()
	connID := "mock"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)

	httpServer, s := newTestServer(t, func(c *Config) { c.Now = time.Now })
	defer httpServer.Close()

	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:           "client-no-restriction",
		RedirectURIs: []string{"cb"},
		// AllowedGroups not set: any authenticated user may complete SSO.
	}))
	require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
		ID:            authReqID,
		ClientID:      "client-no-restriction",
		ConnectorID:   connID,
		RedirectURI:   "cb",
		Expiry:        expiry,
		ResponseTypes: []string{oauth2.ResponseTypeCode},
	}))

	rr := httptest.NewRecorder()
	path := fmt.Sprintf("/callback/%s?state=%s", connID, authReqID)
	s.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	require.Equal(t, 303, rr.Code)

	_, restPath := followFlow(t, s, rr)
	require.Equal(t, "/cb", restPath)
}

func TestClientAllowedGroups_PasswordLoginDeny(t *testing.T) {
	ctx := t.Context()
	connID := "mockPw"
	authReqID := "test"
	expiry := time.Now().Add(100 * time.Second)

	httpServer, s := newTestServer(t, func(c *Config) { c.Now = time.Now })
	defer httpServer.Close()

	require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
		ID:            "client-pw-deny",
		RedirectURIs:  []string{"cb"},
		AllowedGroups: []string{"some-group"}, // mockPassword returns an identity with no groups
	}))
	require.NoError(t, s.storage.CreateConnector(ctx, storage.Connector{
		ID:              connID,
		Type:            "mockPassword",
		Name:            "MockPassword",
		ResourceVersion: "1",
		Config:          []byte(`{"username": "foo", "password": "password"}`),
	}))
	require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
		ID:            authReqID,
		ClientID:      "client-pw-deny",
		ConnectorID:   connID,
		RedirectURI:   "cb",
		Expiry:        expiry,
		ResponseTypes: []string{oauth2.ResponseTypeCode},
	}))

	rr := httptest.NewRecorder()
	path := fmt.Sprintf("/auth/%s/login?state=%s&back=&login=foo&password=password", connID, authReqID)
	s.ServeHTTP(rr, httptest.NewRequest("POST", path, nil))
	require.Equal(t, http.StatusForbidden, rr.Code, "user with no groups must be rejected when client has AllowedGroups")
}

// TestClientAllowedGroups_TokenScope verifies that when a client has
// AllowedGroups, dex fetches groups from the connector for the server-side
// check (scopesForConnector), but only puts a "groups" claim in the issued
// token when the auth request actually asked for the "groups" scope.
func TestClientAllowedGroups_TokenScope(t *testing.T) {
	tests := []struct {
		name       string
		scopes     []string
		wantGroups []string
	}{
		{name: "groups scope not requested", scopes: []string{"openid"}, wantGroups: nil},
		{name: "groups scope requested", scopes: []string{"openid", "groups"}, wantGroups: []string{"authors"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			connID := "mock"
			authReqID := "test"
			redirectURI := "http://localhost/callback"
			expiry := time.Now().Add(100 * time.Second)

			httpServer, s := newTestServer(t, func(c *Config) { c.Now = time.Now })
			defer httpServer.Close()

			require.NoError(t, s.storage.CreateClient(ctx, storage.Client{
				ID:            "client-token-scope",
				Secret:        "secret",
				RedirectURIs:  []string{redirectURI},
				AllowedGroups: []string{"authors"}, // matches the mock connector's identity
			}))
			require.NoError(t, s.storage.CreateAuthRequest(ctx, storage.AuthRequest{
				ID:            authReqID,
				ClientID:      "client-token-scope",
				ConnectorID:   connID,
				RedirectURI:   redirectURI,
				Expiry:        expiry,
				ResponseTypes: []string{oauth2.ResponseTypeCode},
				Scopes:        tc.scopes,
			}))

			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/callback/%s?state=%s", connID, authReqID), nil)
			s.ServeHTTP(rr, req)
			require.Equal(t, 303, rr.Code)

			rr, restPath := followFlow(t, s, rr)
			require.Equal(t, "/callback", restPath)

			loc, err := url.Parse(rr.Header().Get("Location"))
			require.NoError(t, err)
			code := loc.Query().Get("code")
			require.NotEmpty(t, code, "redirect should carry an authorization code")

			vals := url.Values{}
			vals.Set("grant_type", "authorization_code")
			vals.Set("code", code)
			vals.Set("redirect_uri", redirectURI)
			vals.Set("client_id", "client-token-scope")
			vals.Set("client_secret", "secret")
			trr := httptest.NewRecorder()
			treq := httptest.NewRequest("POST", httpServer.URL+"/token", strings.NewReader(vals.Encode()))
			treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			s.ServeHTTP(trr, treq)
			require.Equal(t, http.StatusOK, trr.Code, "token exchange: %s", trr.Body.String())

			var tokenResp struct {
				IDToken string `json:"id_token"`
			}
			require.NoError(t, json.Unmarshal(trr.Body.Bytes(), &tokenResp))
			require.NotEmpty(t, tokenResp.IDToken)

			p, err := oidc.NewProvider(ctx, httpServer.URL)
			require.NoError(t, err)
			idToken, err := p.Verifier(&oidc.Config{SkipClientIDCheck: true}).Verify(ctx, tokenResp.IDToken)
			require.NoError(t, err)

			var claims struct {
				Groups []string `json:"groups"`
			}
			require.NoError(t, idToken.Claims(&claims))
			require.Equal(t, tc.wantGroups, claims.Groups)
		})
	}
}
