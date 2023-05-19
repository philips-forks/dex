package hsdp_test

//nolint
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/hsdp"
	"github.com/philips-software/go-dip-api/iam"
	"gopkg.in/square/go-jose.v2"
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
			receivedCodeVerifier := make(chan string, 1)
			testServer, iamServer, idmServer, err := setupServers(tc.token, func(r *http.Request) {
				receivedCodeVerifier <- r.FormValue("code_verifier")
			})
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
			}

			conn, err := newConnector(config)
			if err != nil {
				t.Fatal("failed to create new connector", err)
			}

			_, connectorData, err := conn.LoginURL(connector.Scopes{}, config.RedirectURI, "state")
			if err != nil {
				t.Fatal("failed to create login URL", err)
			}
			codeVerifier := verifierFromConnectorData(t, connectorData)

			req, err := newRequestWithAuthCode(testServer.URL, "someCode")
			if err != nil {
				t.Fatal("failed to create request", err)
			}

			identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, connectorData, req)
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
			if got := <-receivedCodeVerifier; got != codeVerifier {
				t.Errorf("expected token exchange code_verifier %q, got %q", codeVerifier, got)
			}
		})
	}
}

func TestLoginURL_PKCE(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:       testServer.URL,
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		IAMURL:       iamServer.URL,
		IDMURL:       idmServer.URL,
		RedirectURI:  fmt.Sprintf("%s/callback", testServer.URL),
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	loginURL, connectorData, err := conn.LoginURL(connector.Scopes{}, config.RedirectURI, "state")
	if err != nil {
		t.Fatal("failed to create login URL", err)
	}

	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatal("failed to parse login URL", err)
	}

	codeVerifier := verifierFromConnectorData(t, connectorData)
	sum := sha256.Sum256([]byte(codeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if got := u.Query().Get("code_challenge"); got != expectedChallenge {
		t.Errorf("expected code_challenge %q, got %q", expectedChallenge, got)
	}
	if got := u.Query().Get("code_challenge_method"); got != "S256" {
		t.Errorf("expected code_challenge_method %q, got %q", "S256", got)
	}
}

func TestHandleCallback_MissingPKCEData(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:       testServer.URL,
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		IAMURL:       iamServer.URL,
		IDMURL:       idmServer.URL,
		RedirectURI:  fmt.Sprintf("%s/callback", testServer.URL),
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	req, err := newRequestWithAuthCode(testServer.URL, "someCode")
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	_, err = conn.HandleCallback(connector.Scopes{}, nil, req)
	if err == nil {
		t.Fatal("expected missing PKCE data to fail")
	}
	if got, want := err.Error(), "hsdp: PKCE data is missing"; got != want {
		t.Errorf("expected error %q, got %q", want, got)
	}
}

func TestHandleCallback_DynamicSAML(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{
		"sub":      "subvalue",
		"username": "username",
		"email":    "emailvalue",
	})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:       testServer.URL,
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		Scopes:       []string{"email"},
		IAMURL:       iamServer.URL,
		IDMURL:       idmServer.URL,
		RedirectURI:  fmt.Sprintf("%s/callback", testServer.URL),
		// saml2LoginURL is deliberately NOT set
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/callback?assertion=testAssertion", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, nil, req)
	if err != nil {
		t.Fatalf("expected dynamic SAML assertion callback to succeed without saml2LoginURL, got: %v", err)
	}

	if identity.UserID != "subvalue" {
		t.Errorf("expected UserID 'subvalue', got '%s'", identity.UserID)
	}
}

func TestHandleCallback_SAMLResponseAlias(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{
		"sub":      "subvalue",
		"username": "username",
		"email":    "emailvalue",
	})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:       testServer.URL,
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		Scopes:       []string{"email"},
		IAMURL:       iamServer.URL,
		IDMURL:       idmServer.URL,
		RedirectURI:  fmt.Sprintf("%s/callback", testServer.URL),
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/callback?SAMLResponse=samlResponseValue", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, nil, req)
	if err != nil {
		t.Fatalf("expected SAMLResponse alias callback to succeed, got: %v", err)
	}

	if identity.UserID != "subvalue" {
		t.Errorf("expected UserID 'subvalue', got '%s'", identity.UserID)
	}
}

func TestHandleCallback_OIDCWithSAMLConfigured(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{
		"sub":      "subvalue",
		"username": "username",
		"email":    "emailvalue",
	})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:        testServer.URL,
		ClientID:      "clientID",
		ClientSecret:  "clientSecret",
		Scopes:        []string{"email"},
		IAMURL:        iamServer.URL,
		IDMURL:        idmServer.URL,
		RedirectURI:   fmt.Sprintf("%s/callback", testServer.URL),
		SAML2LoginURL: "https://saml.example.com/login",
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	req, err := newRequestWithAuthCode(testServer.URL+"/callback", "someCode")
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	identity, err := conn.HandleCallback(connector.Scopes{Groups: true}, nil, req)
	if err != nil {
		t.Fatalf("expected OIDC code callback to succeed with SAML configured, got: %v", err)
	}

	if identity.UserID != "subvalue" {
		t.Errorf("expected UserID 'subvalue', got '%s'", identity.UserID)
	}
}

func TestHandleCallback_MissingParams(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:       testServer.URL,
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		IAMURL:       iamServer.URL,
		IDMURL:       idmServer.URL,
		RedirectURI:  fmt.Sprintf("%s/callback", testServer.URL),
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/callback", nil)
	if err != nil {
		t.Fatal("failed to create request", err)
	}

	_, err = conn.HandleCallback(connector.Scopes{}, nil, req)
	if err == nil {
		t.Fatal("expected error when both code and assertion are missing, got nil")
	}

	expectedErrMsg := `hsdp: callback request missing both "code" and "assertion" parameters`
	if err.Error() != expectedErrMsg {
		t.Errorf("expected error message %q, got %q", expectedErrMsg, err.Error())
	}
}

func setupServers(tok map[string]interface{}, tokenRequestObservers ...func(*http.Request)) (dexmux *httptest.Server, iammux *httptest.Server, idmmux *httptest.Server, err error) {
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
		for _, observe := range tokenRequestObservers {
			observe(r)
		}

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
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	conn, err := config.Open("id", log)
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

func verifierFromConnectorData(t *testing.T, connectorData []byte) string {
	t.Helper()

	var data struct {
		CodeVerifier string `json:"codeVerifier"`
	}
	if err := json.Unmarshal(connectorData, &data); err != nil {
		t.Fatal("failed to parse PKCE connector data", err)
	}
	if data.CodeVerifier == "" {
		t.Fatal("PKCE connector data did not contain a code verifier")
	}
	return data.CodeVerifier
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

func TestStateViaCookieConfig(t *testing.T) {
	testServer, iamServer, idmServer, err := setupServers(map[string]interface{}{})
	if err != nil {
		t.Fatal("failed to setup test server", err)
	}
	defer testServer.Close()
	defer iamServer.Close()
	defer idmServer.Close()

	config := hsdp.Config{
		Issuer:         testServer.URL,
		ClientID:       "clientID",
		ClientSecret:   "clientSecret",
		IAMURL:         iamServer.URL,
		IDMURL:         idmServer.URL,
		RedirectURI:    fmt.Sprintf("%s/callback", testServer.URL),
		StateViaCookie: true,
	}
	if !config.StateViaCookie {
		t.Errorf("expected config.StateViaCookie to be true")
	}

	conn, err := newConnector(config)
	if err != nil {
		t.Fatal("failed to create connector", err)
	}
	if !conn.StateViaCookie() {
		t.Errorf("expected conn.StateViaCookie() to be true")
	}
}
