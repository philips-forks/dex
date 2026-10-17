package hsdp_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/hsdp"
)

// addGroups must land on identity.Groups during HandleCallback, so a
// client's AllowedGroups check (run before any token is minted) can match on
// them — merged with the IAM role groups when those are enabled.
func TestHandleCallback_AddGroups(t *testing.T) {
	tok := map[string]interface{}{
		"sub":         "subvalue",
		"name":        "namevalue",
		"username":    "username",
		"email":       "emailvalue",
		"given_name":  "givenname",
		"family_name": "familyname",
		"organizations": map[string]interface{}{
			"organizationList": []map[string]interface{}{
				{
					"organizationId": "org1",
					"roles":          []string{"Admin"},
				},
			},
		},
	}

	tests := []struct {
		name            string
		enableRoleClaim bool
		addGroups       []string
		want            []string
	}{
		{
			name:      "addGroups only",
			addGroups: []string{"customer:acme", "", "customer:acme"},
			want:      []string{"customer:acme"},
		},
		{
			name:            "merged with IAM role groups",
			enableRoleClaim: true,
			addGroups:       []string{"customer:acme", "urn:iamr:org1:admin"},
			want:            []string{"urn:iamr:org1:admin", "customer:acme"},
		},
		{
			name:            "no addGroups keeps role groups unchanged",
			enableRoleClaim: true,
			want:            []string{"urn:iamr:org1:admin"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer, iamServer, idmServer, err := setupServers(tok)
			if err != nil {
				t.Fatal("failed to setup test server", err)
			}
			defer testServer.Close()
			defer iamServer.Close()
			defer idmServer.Close()

			basicAuth := true
			config := hsdp.Config{
				Issuer:               testServer.URL,
				ClientID:             "clientID",
				ClientSecret:         "clientSecret",
				Scopes:               []string{"email", "groups"},
				IAMURL:               iamServer.URL,
				IDMURL:               idmServer.URL,
				RedirectURI:          fmt.Sprintf("%s/callback", testServer.URL),
				BasicAuthUnsupported: &basicAuth,
				EnableRoleClaim:      tc.enableRoleClaim,
				AddGroups:            tc.addGroups,
			}

			conn, err := newConnector(config)
			if err != nil {
				t.Fatal("failed to create new connector", err)
			}

			_, connectorData, err := conn.LoginURL(connector.Scopes{}, config.RedirectURI, "state")
			if err != nil {
				t.Fatal("failed to create login URL", err)
			}

			req, err := newRequestWithAuthCode(testServer.URL, "someCode")
			if err != nil {
				t.Fatal("failed to create request", err)
			}

			identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, connectorData, req)
			if err != nil {
				t.Fatal("handle callback failed", err)
			}

			if !reflect.DeepEqual(identity.Groups, tc.want) {
				t.Errorf("identity.Groups = %+v, want %+v", identity.Groups, tc.want)
			}
		})
	}
}

// addGroups must always end up in the token's groups claim, whichever of
// enableGroupClaim/enableRoleClaim/roleAsGroupClaim produced (or replaced)
// that claim before it.
func TestExtendPayload_AddGroups(t *testing.T) {
	var cd hsdp.ConnectorData
	if err := json.Unmarshal([]byte(`{"Introspect": {
		"sub": "subvalue",
		"username": "username",
		"organizations": {"organizationList": [
			{"organizationId": "org1", "roles": ["Admin"], "groups": ["Ops"]}
		]}
	}}`), &cd); err != nil {
		t.Fatal(err)
	}
	cdata, err := json.Marshal(cd)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name             string
		config           hsdp.Config
		payloadGroups    []string
		wantGroups       []string
		wantGroupsAbsent bool
	}{
		{
			name:       "no group or role claim: groups is just addGroups",
			config:     hsdp.Config{AddGroups: []string{"customer:acme"}},
			wantGroups: []string{"customer:acme"},
		},
		{
			name:          "keeps groups Dex already put in the payload",
			config:        hsdp.Config{AddGroups: []string{"customer:acme", "existing"}},
			payloadGroups: []string{"existing"},
			wantGroups:    []string{"existing", "customer:acme"},
		},
		{
			name:       "enableGroupClaim: IAM groups plus addGroups",
			config:     hsdp.Config{EnableGroupClaim: true, AddGroups: []string{"customer:acme"}},
			wantGroups: []string{"urn:iamg:org1:ops", "customer:acme"},
		},
		{
			name:       "roleAsGroupClaim: IAM roles plus addGroups",
			config:     hsdp.Config{EnableRoleClaim: true, RoleAsGroupClaim: true, AddGroups: []string{"customer:acme"}},
			wantGroups: []string{"urn:iamr:org1:admin", "customer:acme"},
		},
		{
			name:             "no addGroups and no group claim: groups stays absent",
			config:           hsdp.Config{},
			wantGroupsAbsent: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{})
			if err != nil {
				t.Fatal("failed to setup test server", err)
			}
			defer testServer.Close()
			defer iamServer.Close()
			defer idmServer.Close()

			tc.config.Issuer = testServer.URL
			tc.config.IAMURL = iamServer.URL
			tc.config.IDMURL = idmServer.URL
			conn, err := newConnector(tc.config)
			if err != nil {
				t.Fatal("failed to create new connector", err)
			}

			claims := map[string]interface{}{"sub": "subvalue"}
			if tc.payloadGroups != nil {
				claims["groups"] = tc.payloadGroups
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}

			out, err := conn.ExtendPayload(nil, payload, cdata)
			if err != nil {
				t.Fatal("ExtendPayload failed", err)
			}

			var got struct {
				Groups *[]string `json:"groups"`
			}
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			if tc.wantGroupsAbsent {
				if got.Groups != nil {
					t.Errorf("groups = %+v, want absent", *got.Groups)
				}
				return
			}
			if got.Groups == nil {
				t.Fatalf("groups claim missing, want %+v", tc.wantGroups)
			}
			if !reflect.DeepEqual(*got.Groups, tc.wantGroups) {
				t.Errorf("groups = %+v, want %+v", *got.Groups, tc.wantGroups)
			}
		})
	}
}
