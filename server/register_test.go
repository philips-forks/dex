package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

func TestDCRDiscovery(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		httpServer, server := newTestServer(t, nil)
		defer httpServer.Close()

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
		require.Equal(t, http.StatusOK, rr.Code)

		var res discovery
		err := json.NewDecoder(rr.Result().Body).Decode(&res)
		require.NoError(t, err)
		assert.Empty(t, res.RegistrationEndpoint)
	})

	t.Run("enabled via config", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
		require.Equal(t, http.StatusOK, rr.Code)

		var res discovery
		err := json.NewDecoder(rr.Result().Body).Decode(&res)
		require.NoError(t, err)
		assert.NotEmpty(t, res.RegistrationEndpoint)
		assert.Contains(t, res.RegistrationEndpoint, "/register")
	})
}

func TestDCRRegistration(t *testing.T) {
	t.Run("register confidential client successfully", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName:    "Test Confidential Client",
			RedirectURIs:  []string{"https://example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)

		var resp dcrResponse
		err = json.NewDecoder(rr.Result().Body).Decode(&resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.ClientID)
		assert.NotEmpty(t, resp.ClientSecret)
		assert.True(t, resp.ClientIDIssuedAt > 0)
		assert.Equal(t, "Test Confidential Client", resp.ClientName)
		assert.Equal(t, []string{"https://example.com/callback"}, resp.RedirectURIs)
		assert.Equal(t, []string{"authorization_code"}, resp.GrantTypes)
		assert.Equal(t, []string{"code"}, resp.ResponseTypes)
		assert.NotEmpty(t, resp.RegistrationAccessToken)
		assert.Contains(t, resp.RegistrationClientURI, "/register/"+resp.ClientID)

		// Verify client exists in storage
		storedClient, err := server.storage.GetClient(t.Context(), resp.ClientID)
		require.NoError(t, err)
		assert.Equal(t, resp.ClientID, storedClient.ID)
		assert.Equal(t, resp.ClientSecret, storedClient.Secret)
		assert.Equal(t, "Test Confidential Client", storedClient.Name)
		assert.False(t, storedClient.Public)
	})

	t.Run("register public client successfully", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName:              "Test Public Client",
			RedirectURIs:            []string{"https://example.com/callback"},
			TokenEndpointAuthMethod: "none",
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusCreated, rr.Code)

		var resp dcrResponse
		err = json.NewDecoder(rr.Result().Body).Decode(&resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.ClientID)
		assert.Empty(t, resp.ClientSecret)
		assert.Equal(t, "Test Public Client", resp.ClientName)
		assert.Equal(t, []string{"authorization_code"}, resp.GrantTypes) // defaulted
		assert.Equal(t, []string{"code"}, resp.ResponseTypes)             // defaulted
		assert.NotEmpty(t, resp.RegistrationAccessToken)

		// Verify client exists in storage
		storedClient, err := server.storage.GetClient(t.Context(), resp.ClientID)
		require.NoError(t, err)
		assert.Equal(t, resp.ClientID, storedClient.ID)
		assert.Empty(t, storedClient.Secret)
		assert.True(t, storedClient.Public)
	})

	t.Run("method must be POST", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/register", nil)

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)

		var errResp map[string]string
		err := json.NewDecoder(rr.Result().Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_request", errResp["error"])
	})

	t.Run("missing redirect uris", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName: "No Redirect Client",
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var errResp map[string]string
		err = json.NewDecoder(rr.Result().Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_redirect_uri", errResp["error"])
	})

	t.Run("invalid redirect URI with fragment", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName:   "Fragment Client",
			RedirectURIs: []string{"https://example.com/callback#fragment"},
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var errResp map[string]string
		err = json.NewDecoder(rr.Result().Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_redirect_uri", errResp["error"])
	})

	t.Run("unsupported auth method", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName:              "Unsupported Auth Client",
			RedirectURIs:            []string{"https://example.com/callback"},
			TokenEndpointAuthMethod: "private_key_jwt",
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var errResp map[string]string
		err = json.NewDecoder(rr.Result().Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_client_metadata", errResp["error"])
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		reqBody := dcrRequest{
			ClientName:   "Unsupported Grant Client",
			RedirectURIs: []string{"https://example.com/callback"},
			GrantTypes:   []string{"client_credentials_custom"},
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))

		server.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var errResp map[string]string
		err = json.NewDecoder(rr.Result().Body).Decode(&errResp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_client_metadata", errResp["error"])
	})
}

func TestDCRClientManagement(t *testing.T) {
	t.Run("GET and DELETE operations", func(t *testing.T) {
		httpServer, server := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
		})
		defer httpServer.Close()

		// 1. POST /register
		reqBody := dcrRequest{
			ClientName:   "Manageable Client",
			RedirectURIs: []string{"https://example.com/callback"},
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(bodyBytes))
		server.ServeHTTP(rr, req)
		require.Equal(t, http.StatusCreated, rr.Code)

		var resp dcrResponse
		err = json.NewDecoder(rr.Result().Body).Decode(&resp)
		require.NoError(t, err)

		clientID := resp.ClientID
		token := resp.RegistrationAccessToken
		require.NotEmpty(t, clientID)
		require.NotEmpty(t, token)

		// 2. GET /register/{client_id} with token
		rrGet := httptest.NewRecorder()
		reqGet := httptest.NewRequest("GET", "/register/"+clientID, nil)
		reqGet.Header.Set("Authorization", "Bearer "+token)
		server.ServeHTTP(rrGet, reqGet)
		assert.Equal(t, http.StatusOK, rrGet.Code)

		var respGet dcrResponse
		err = json.NewDecoder(rrGet.Result().Body).Decode(&respGet)
		require.NoError(t, err)
		assert.Equal(t, clientID, respGet.ClientID)
		assert.Equal(t, "Manageable Client", respGet.ClientName)
		assert.NotEmpty(t, respGet.RegistrationAccessToken)

		// 3. GET /register/{client_id} without token -> 401
		rrGetNoAuth := httptest.NewRecorder()
		reqGetNoAuth := httptest.NewRequest("GET", "/register/"+clientID, nil)
		server.ServeHTTP(rrGetNoAuth, reqGetNoAuth)
		assert.Equal(t, http.StatusUnauthorized, rrGetNoAuth.Code)

		// 4. GET /register/{client_id} with another client's token -> 403
		// We'll generate a token for another client ID
		badToken := server.generateRegistrationToken("other-client-id")

		rrGetBadAuth := httptest.NewRecorder()
		reqGetBadAuth := httptest.NewRequest("GET", "/register/"+clientID, nil)
		reqGetBadAuth.Header.Set("Authorization", "Bearer "+badToken)
		server.ServeHTTP(rrGetBadAuth, reqGetBadAuth)
		assert.Equal(t, http.StatusForbidden, rrGetBadAuth.Code)

		// 5. DELETE /register/{client_id} with token -> 204
		rrDel := httptest.NewRecorder()
		reqDel := httptest.NewRequest("DELETE", "/register/"+clientID, nil)
		reqDel.Header.Set("Authorization", "Bearer "+token)
		server.ServeHTTP(rrDel, reqDel)
		assert.Equal(t, http.StatusNoContent, rrDel.Code)

		// 6. Verify client no longer exists in storage
		_, err = server.storage.GetClient(t.Context(), clientID)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("stable tokens with configured DCRSecret", func(t *testing.T) {
		secretKey := []byte("this-is-a-very-stable-secret-key-12345")
		
		// Create a server with a configured secret key
		_, server1 := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
			c.DCRSecret = secretKey
		})
		
		token1 := server1.generateRegistrationToken("some-client-id")
		
		// Create another server instance mimicking restart/re-creation with the same secret key
		_, server2 := newTestServer(t, func(c *Config) {
			c.EnableDCR = true
			c.DCRSecret = secretKey
		})
		
		verifiedClientID, err := server2.verifyRegistrationToken(token1)
		require.NoError(t, err)
		assert.Equal(t, "some-client-id", verifiedClientID)
	})
}
