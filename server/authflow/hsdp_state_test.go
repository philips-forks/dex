package authflow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/mock"
	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/storage"
)

// mockCookieCallback wraps the mock callback connector to report StateViaCookie,
// the interface connectors like hsdp implement when their upstream redirect
// drops the "state" query parameter.
type mockCookieCallback struct {
	connector.CallbackConnector
	cookieState bool
}

func (m *mockCookieCallback) StateViaCookie() bool {
	return m.cookieState
}

func TestHandleConnectorCallback_StateViaCookie(t *testing.T) {
	httpServer, server := newTestHandler(t, nil)
	defer httpServer.Close()

	ctx := t.Context()
	connID := "hsdp-test"

	require.NoError(t, server.Storage.CreateConnector(ctx, storage.Connector{
		ID:              connID,
		Type:            "mockCallback",
		Name:            "Mock",
		ResourceVersion: "1",
	}))
	mockConn := &mockCookieCallback{
		CallbackConnector: mock.NewCallbackConnector(nil).(connector.CallbackConnector),
		cookieState:       true,
	}
	server.Connectors.Set(connID, connectors.Connector{ResourceVersion: "1", Connector: mockConn})

	client := storage.Client{
		ID:           "test-client",
		Secret:       "test-secret",
		RedirectURIs: []string{"http://example.com/callback"},
	}
	require.NoError(t, server.Storage.CreateClient(ctx, client))

	// 1. Initiate login via /auth/hsdp-test.
	authReqURL := fmt.Sprintf("%s/auth/%s?response_type=code&client_id=test-client&redirect_uri=http://example.com/callback&scope=openid", httpServer.URL, connID)
	req := httptest.NewRequest(http.MethodGet, authReqURL, nil)
	rr := httptest.NewRecorder()
	server.ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)

	var hsdpCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == hsdpStateCookie {
			hsdpCookie = c
			break
		}
	}
	require.NotNil(t, hsdpCookie, "expected hsdp_state cookie to be set")
	require.NotEmpty(t, hsdpCookie.Value)

	// 2. Simulate callback without state query param, but with hsdp_state cookie.
	callbackURL := fmt.Sprintf("%s/callback/%s", httpServer.URL, connID)
	callbackReq := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackReq.AddCookie(hsdpCookie)
	callbackRR := httptest.NewRecorder()
	server.ServeHTTP(callbackRR, callbackReq)

	require.Equal(t, http.StatusSeeOther, callbackRR.Code)

	// The callback hands off to the /auth dispatcher, which (SkipApproval, no
	// MFA) issues immediately and redirects to the client's redirect_uri; follow
	// whatever internal hops it takes to get there.
	loc := callbackRR.Header().Get("Location")
	for range 5 {
		if strings.Contains(loc, "http://example.com/callback") {
			break
		}
		req := httptest.NewRequest(http.MethodGet, loc, nil)
		next := httptest.NewRecorder()
		server.ServeHTTP(next, req)
		loc = next.Header().Get("Location")
	}
	require.Contains(t, loc, "http://example.com/callback")

	var clearedCookie *http.Cookie
	for _, c := range callbackRR.Result().Cookies() {
		if c.Name == hsdpStateCookie {
			clearedCookie = c
			break
		}
	}
	require.NotNil(t, clearedCookie, "expected hsdp_state cookie clear header in response")
	require.Equal(t, -1, clearedCookie.MaxAge)
}
