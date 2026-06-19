package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

// mintIDJAG drives Role A (token exchange -> ID-JAG) and returns the ID-JAG.
func mintIDJAG(t *testing.T, httpServer *httptest.Server, s *Server, clientID, secret, audience, resource string, scopes []string) string {
	t.Helper()
	subjectToken := makeTestJWTWithEmail(t, httpServer.URL, "user-123", clientID, "user@example.com", true)

	vals := url.Values{}
	vals.Set("grant_type", grantTypeTokenExchange)
	vals.Set("requested_token_type", tokenTypeIDJAG)
	vals.Set("subject_token_type", tokenTypeID)
	vals.Set("subject_token", subjectToken)
	vals.Set("connector_id", "mock")
	vals.Set("audience", audience)
	if resource != "" {
		vals.Set("resource", resource)
	}
	if len(scopes) > 0 {
		vals.Set("scope", strings.Join(scopes, " "))
	}
	vals.Set("client_id", clientID)
	vals.Set("client_secret", secret)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(vals.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	s.handleToken(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "mint ID-JAG body: %s", rr.Body.String())
	var res accessTokenResponse
	require.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&res))
	require.Equal(t, tokenTypeIDJAG, res.IssuedTokenType)
	return res.AccessToken
}

// setupDexToDexEMA configures a single Dex instance that acts as both the
// enterprise IdP (Role A, ID-JAG issuance) and the MCP Authorization Server
// (Role B, jwt-bearer redemption). Its own issuer is the expected audience.
func setupDexToDexEMA(t *testing.T) (*httptest.Server, *Server) {
	return newTestServer(t, func(c *Config) {
		require.NoError(t, c.Storage.CreateClient(t.Context(), storage.Client{
			ID:     "mcp-client",
			Secret: "mcp-secret",
		}))
		c.AllowedGrantTypes = append(c.AllowedGrantTypes, grantTypeJWTBearer)
		c.TokenExchange = TokenExchangeConfig{TokenTypes: []string{tokenTypeIDJAG}}
		c.IDJAGPolicies = []TokenExchangePolicy{
			{ClientID: "mcp-client", AllowedAudiences: []string{c.Issuer}},
		}
		c.EnterpriseManagedAuthorization = EMAConfig{
			Enabled:               true,
			AccountLinkingByEmail: true,
			TrustedIssuers: []TrustedIssuer{
				{
					Issuer:           c.Issuer,
					JWKSURL:          c.Issuer + "/keys",
					ExpectedAudience: c.Issuer,
				},
			},
		}
	})
}

func redeemIDJAG(t *testing.T, httpServer *httptest.Server, s *Server, idjag string) *httptest.ResponseRecorder {
	t.Helper()
	vals := url.Values{}
	vals.Set("grant_type", grantTypeJWTBearer)
	vals.Set("assertion", idjag)
	vals.Set("client_id", "mcp-client")
	vals.Set("client_secret", "mcp-secret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(vals.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	s.handleToken(rr, req)
	return rr
}

// TestEMA_DexToDex_EndToEnd exercises the full triangle on a single Dex:
// mint an ID-JAG (Role A) and redeem it for a resource-bound access token (Role B).
func TestEMA_DexToDex_EndToEnd(t *testing.T) {
	httpServer, s := setupDexToDexEMA(t)
	defer httpServer.Close()

	resource := "https://mcp.chat.example/"
	idjag := mintIDJAG(t, httpServer, s, "mcp-client", "mcp-secret", httpServer.URL, resource, []string{"chat.read"})

	rr := redeemIDJAG(t, httpServer, s, idjag)
	require.Equal(t, http.StatusOK, rr.Code, "redeem body: %s", rr.Body.String())

	var res accessTokenResponse
	require.NoError(t, json.NewDecoder(rr.Result().Body).Decode(&res))
	require.Equal(t, "bearer", res.TokenType)
	require.NotEmpty(t, res.AccessToken)
	require.Equal(t, "chat.read", res.Scope)

	// The issued access token MUST be audience-restricted to the MCP server
	// resource (EMA §5.1), not the requesting client.
	claims := decodeJWTPayload(t, res.AccessToken)
	// A single-element audience marshals as a plain string (Dex audience.MarshalJSON).
	require.Equal(t, resource, claims["aud"], "access token aud must be the resource")
	require.Equal(t, "user-123", claims["sub"])
	require.Equal(t, "user@example.com", claims["email"], "account linking should carry email")
}

// TestEMA_DexToDex_MissingResource verifies that an ID-JAG with no resource
// claim is rejected at redemption, since there is no audience to bind to.
func TestEMA_DexToDex_MissingResource(t *testing.T) {
	httpServer, s := setupDexToDexEMA(t)
	defer httpServer.Close()

	idjag := mintIDJAG(t, httpServer, s, "mcp-client", "mcp-secret", httpServer.URL, "", []string{"chat.read"})

	rr := redeemIDJAG(t, httpServer, s, idjag)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_grant")
}

// TestEMA_Redeem_WrongAudience verifies an ID-JAG minted for a different
// audience (not this MCP AS) is rejected.
func TestEMA_Redeem_WrongAudience(t *testing.T) {
	httpServer, s := setupDexToDexEMA(t)
	defer httpServer.Close()

	// Allow the client to request a foreign audience, then mint for it.
	s.tokenExchangePolicies = []TokenExchangePolicy{
		{ClientID: "mcp-client", AllowedAudiences: []string{"https://other-as.example/"}},
	}
	idjag := mintIDJAG(t, httpServer, s, "mcp-client", "mcp-secret", "https://other-as.example/", "https://mcp.chat.example/", []string{"chat.read"})

	rr := redeemIDJAG(t, httpServer, s, idjag)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_grant")
}

// TestEMA_Redeem_MissingAssertion verifies the assertion parameter is required.
func TestEMA_Redeem_MissingAssertion(t *testing.T) {
	httpServer, s := setupDexToDexEMA(t)
	defer httpServer.Close()

	vals := url.Values{}
	vals.Set("grant_type", grantTypeJWTBearer)
	vals.Set("client_id", "mcp-client")
	vals.Set("client_secret", "mcp-secret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(vals.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	s.handleToken(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "invalid_request")
}

// TestEMA_Discovery verifies the EMA grant profile is advertised when enabled.
func TestEMA_Discovery(t *testing.T) {
	httpServer, s := setupDexToDexEMA(t)
	defer httpServer.Close()

	d := s.constructDiscovery(t.Context())
	require.Contains(t, d.GrantProfilesSupported, idJAGGrantProfile)
}

// TestEMA_Disabled verifies jwt-bearer is rejected when EMA is off.
func TestEMA_Disabled(t *testing.T) {
	httpServer, s := newTestServer(t, func(c *Config) {
		require.NoError(t, c.Storage.CreateClient(t.Context(), storage.Client{
			ID:     "mcp-client",
			Secret: "mcp-secret",
		}))
	})
	defer httpServer.Close()

	rr := redeemIDJAG(t, httpServer, s, "irrelevant")
	// jwt-bearer is not in supportedGrantTypes, so the dispatcher rejects it.
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "unsupported_grant_type")

	d := s.constructDiscovery(t.Context())
	require.NotContains(t, d.GrantProfilesSupported, idJAGGrantProfile)
}
