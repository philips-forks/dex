package hsdp_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dexidp/dex/connector/hsdp"

	"github.com/philips-software/go-hsdp-api/iam"
	"gopkg.in/square/go-jose.v2"

	"github.com/dexidp/dex/connector"
)

func TestHandleCallback(t *testing.T) {
	t.Helper()

	tests := []struct {
		name           string
		scopes         []string
		expectUserID   string
		expectUserName string
		token          map[string]interface{}
	}{
		{
			name:           "simpleCase",
			expectUserID:   "subvalue",
			expectUserName: "username",
			token: map[string]interface{}{
				"sub":         "subvalue",
				"name":        "namevalue",
				"username":    "username",
				"email":       "emailvalue",
				"given_name":  "givenname",
				"family_name": "familyname",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testServer, iamServer, idmServer, err := setupServers(tc.token)
			if err != nil {
				t.Fatal("failed to setup test server", err)
			}
			defer testServer.Close()
			defer iamServer.Close()
			defer idmServer.Close()

			var scopes []string
			if len(tc.scopes) > 0 {
				scopes = tc.scopes
			} else {
				scopes = []string{"email", "groups"}
			}
			serverURL := testServer.URL
			basicAuth := true
			config := hsdp.Config{
				Issuer:               serverURL,
				ClientID:             "clientID",
				ClientSecret:         "clientSecret",
				Scopes:               scopes,
				IAMURL:               iamServer.URL,
				IDMURL:               idmServer.URL,
				RedirectURI:          fmt.Sprintf("%s/callback", serverURL),
				BasicAuthUnsupported: &basicAuth,
				TenantGroups:         []string{"logreaders"},
				AudienceTrustMap: map[string]string{
					"clientID": "tenantID",
				},
			}

			conn, err := newConnector(config)
			if err != nil {
				t.Fatal("failed to create new connector", err)
			}

			req, err := newRequestWithAuthCode(testServer.URL, "someCode")
			if err != nil {
				t.Fatal("failed to create request", err)
			}

			identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, req)
			if err != nil {
				t.Fatal("handle callback failed", err)
			}

			if !reflect.DeepEqual(identity.UserID, tc.expectUserID) {
				t.Errorf("Expected %+v to equal %+v", identity.UserID, tc.expectUserID)
			}
			if !reflect.DeepEqual(identity.Username, tc.expectUserName) {
				t.Errorf("Expected %+v to equal %+v", identity.Username, tc.expectUserName)
			}
			if !reflect.DeepEqual(identity.EmailVerified, true) {
				t.Errorf("Expected %+v to equal %+v", identity.EmailVerified, true)
			}
		})
	}
}

func setupServers(tok map[string]interface{}) (dexmux *httptest.Server, iammux *httptest.Server, idmmux *httptest.Server, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate rsa key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     "keyId",
		Algorithm: "RSA",
	}

	// DEX Server
	mux := http.NewServeMux()

	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(&map[string]interface{}{
			"keys": []map[string]interface{}{{
				"alg": jwk.Algorithm,
				"kty": jwk.Algorithm,
				"kid": jwk.KeyID,
				"n":   n(&key.PublicKey),
				"e":   e(&key.PublicKey),
			}},
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)
		tok["iss"] = url
		tok["exp"] = time.Now().Add(time.Hour).Unix()
		tok["aud"] = "clientID"
		tok["user_name"] = "subvalue"
		tok["name"] = "subvalue"
		token, err := newToken(&jwk, tok)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&map[string]string{
			"access_token": token,
			"id_token":     token,
			"token_type":   "Bearer",
		})
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("http://%s", r.Host)

		json.NewEncoder(w).Encode(&map[string]string{
			"issuer":                 url,
			"token_endpoint":         fmt.Sprintf("%s/token", url),
			"authorization_endpoint": fmt.Sprintf("%s/authorize", url),
			"userinfo_endpoint":      fmt.Sprintf("%s/userinfo", url),
			"jwks_uri":               fmt.Sprintf("%s/keys", url),
			"introspection_endpoint": fmt.Sprintf("%s/introspect", url),
		})
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&iam.IntrospectResponse{
			Active:   true,
			Username: tok["username"].(string),
			Sub:      tok["sub"].(string),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tok)
	})

	up := struct {
		Status string
	}{
		Status: "OK",
	}

	// IAM Server
	iamMUX := http.NewServeMux()
	iamMUX.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(up)
	})

	// IDM Server
	idmMUX := http.NewServeMux()
	idmMUX.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(up)
	})

	type exchange struct {
		LoginID string      `json:"loginId"`
		Profile iam.Profile `json:"profile"`
	}
	responseStruct := struct {
		Exchange        exchange `json:"exchange"`
		ResponseCode    string   `json:"responseCode"`
		ResponseMessage string   `json:"responseMessage"`
	}{
		Exchange: exchange{
			LoginID: "rwanson",
			Profile: iam.Profile{
				GivenName:  "Ron",
				FamilyName: "Swanson",
			},
		},
		ResponseCode:    "OK",
		ResponseMessage: "OK",
	}

	idmMUX.HandleFunc("/security/users/subvalue", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responseStruct)
	})

	return httptest.NewServer(mux), httptest.NewServer(iamMUX), httptest.NewServer(idmMUX), nil
}

func newToken(key *jose.JSONWebKey, claims map[string]interface{}) (string, error) {
	signingKey := jose.SigningKey{
		Key:       key,
		Algorithm: jose.RS256,
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create new signer: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %v", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %v", err)
	}
	return signature.CompactSerialize()
}

func newConnector(config hsdp.Config) (*hsdp.HSDPConnector, error) {
	logger := slog.Default()
	conn, err := config.Open("id", logger)
	if err != nil {
		return nil, fmt.Errorf("unable to open: %v", err)
	}

	hsdpConn, ok := conn.(*hsdp.HSDPConnector)
	if !ok {
		return nil, errors.New("failed to convert to HSDPConnector")
	}

	return hsdpConn, nil
}

func newRequestWithAuthCode(serverURL string, code string) (*http.Request, error) {
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	values := req.URL.Query()
	values.Add("code", code)
	req.URL.RawQuery = values.Encode()

	return req, nil
}

func n(pub *rsa.PublicKey) string {
	return encode(pub.N.Bytes())
}

func e(pub *rsa.PublicKey) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(pub.E))
	return encode(bytes.TrimLeft(data, "\x00"))
}

func encode(payload []byte) string {
	result := base64.URLEncoding.EncodeToString(payload)
	return strings.TrimRight(result, "=")
}
