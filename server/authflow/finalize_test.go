package authflow

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/session"
	"github.com/dexidp/dex/storage"
)

func TestFinalizeLoginBlockedAccount(t *testing.T) {
	t.Setenv("DEX_SESSIONS_ENABLED", "true")

	httpServer, server := newTestHandler(t, func(c *testFlowConfig) {
		c.SessionConfig = &session.Config{AbsoluteLifetime: time.Hour, ValidIfNotUsedFor: time.Hour}
	})
	defer httpServer.Close()

	ctx := t.Context()

	ident := connector.Identity{UserID: "user-1", Email: "user@example.com"}
	authReq := storage.AuthRequest{
		ID:          "login-req",
		ClientID:    "example-app",
		Expiry:      time.Now().Add(time.Hour),
		ConnectorID: "mock",
	}
	require.NoError(t, server.Storage.CreateClient(ctx, storage.Client{ID: "example-app"}))
	require.NoError(t, server.Storage.CreateAuthRequest(ctx, authReq))
	require.NoError(t, server.Storage.CreateUserIdentity(ctx, storage.UserIdentity{
		UserID:              "user-1",
		ConnectorID:         "mock",
		Claims:              storage.Claims{UserID: "user-1", Email: "user@example.com"},
		Consents:            map[string][]string{},
		MFASecrets:          map[string]*storage.MFASecret{},
		WebAuthnCredentials: map[string][]storage.WebAuthnCredential{},
		CreatedAt:           time.Now(),
		LastLogin:           time.Now(),
		BlockedUntil:        time.Now().Add(time.Hour),
	}))

	// Blocked: finalizeLogin must reject without marking the request logged in.
	_, err := server.finalizeLogin(ctx, ident, authReq, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "locked")

	updated, err := server.Storage.GetAuthRequest(ctx, authReq.ID)
	require.NoError(t, err)
	require.False(t, updated.LoggedIn, "blocked account must not be logged in")

	// Clear the block: login should now proceed.
	require.NoError(t, server.Storage.UpdateUserIdentity(ctx, "user-1", "mock", func(u storage.UserIdentity) (storage.UserIdentity, error) {
		u.BlockedUntil = time.Time{}
		return u, nil
	}))
	_, err = server.finalizeLogin(ctx, ident, authReq, nil)
	require.NoError(t, err)
}

// The authorization code flow's success line is the only record of a login that
// operators get, and without the client it cannot answer which application was
// signed in to when several share a connector.
func TestFinalizeLoginLogsClientID(t *testing.T) {
	var logBuf bytes.Buffer
	httpServer, server := newTestHandler(t, func(c *testFlowConfig) {
		c.Logger = slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	})
	defer httpServer.Close()

	ctx := t.Context()

	authReq := storage.AuthRequest{
		ID:          "login-req",
		ClientID:    "example-app",
		Expiry:      time.Now().Add(time.Hour),
		ConnectorID: "mock",
	}
	require.NoError(t, server.Storage.CreateClient(ctx, storage.Client{ID: "example-app"}))
	require.NoError(t, server.Storage.CreateAuthRequest(ctx, authReq))

	ident := connector.Identity{UserID: "user-1", Email: "user@example.com"}
	_, err := server.finalizeLogin(ctx, ident, authReq, nil)
	require.NoError(t, err)

	var logged bool
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] != "login successful" {
			continue
		}
		logged = true
		require.Equal(t, "example-app", record["client_id"])
	}
	require.True(t, logged, "finalizeLogin did not log a successful login")
}

// A client's AllowedGroups is checked against the groups the connector put on
// the identity (e.g. fixed groups a connector injects for all of its users),
// before the login is completed.
func TestFinalizeLoginClientAllowedGroups(t *testing.T) {
	for _, tc := range []struct {
		name    string
		groups  []string
		allowed bool
	}{
		{name: "connector-provided group allows", groups: []string{"other", "customer:acme"}, allowed: true},
		{name: "glob match allows", groups: []string{"customer:acme-eu"}, allowed: true},
		{name: "missing group denies", groups: []string{"other"}, allowed: false},
		{name: "no groups denies", groups: nil, allowed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpServer, server := newTestHandler(t, nil)
			defer httpServer.Close()

			ctx := t.Context()
			require.NoError(t, server.Storage.CreateClient(ctx, storage.Client{
				ID:            "example-app",
				AllowedGroups: []string{"customer:acme", "customer:acme-*"},
			}))
			authReq := storage.AuthRequest{
				ID:          "login-req",
				ClientID:    "example-app",
				Expiry:      time.Now().Add(time.Hour),
				ConnectorID: "mock",
			}
			require.NoError(t, server.Storage.CreateAuthRequest(ctx, authReq))

			ident := connector.Identity{UserID: "user-1", Email: "user@example.com", Groups: tc.groups}
			_, err := server.finalizeLogin(ctx, ident, authReq, nil)

			updated, getErr := server.Storage.GetAuthRequest(ctx, authReq.ID)
			require.NoError(t, getErr)
			if tc.allowed {
				require.NoError(t, err)
				require.True(t, updated.LoggedIn)
				return
			}
			var notInGroups *connector.UserNotInRequiredGroupsError
			require.ErrorAs(t, err, &notInGroups)
			require.False(t, updated.LoggedIn, "user outside AllowedGroups must not be logged in")
		})
	}
}
