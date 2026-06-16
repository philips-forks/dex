package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux"

	"github.com/dexidp/dex/storage"
)

type dcrRequest struct {
	RedirectURIs            []string         `json:"redirect_uris"`
	TokenEndpointAuthMethod string           `json:"token_endpoint_auth_method"`
	GrantTypes              []string         `json:"grant_types"`
	ResponseTypes           []string         `json:"response_types"`
	ClientName              string           `json:"client_name"`
	ClientURI               string           `json:"client_uri"`
	LogoURI                 string           `json:"logo_uri"`
	Scope                   string           `json:"scope"`
	Contacts                []string         `json:"contacts"`
	TosURI                  string           `json:"tos_uri"`
	PolicyURI               string           `json:"policy_uri"`
	JwksURI                 string           `json:"jwks_uri"`
	Jwks                    *json.RawMessage `json:"jwks"`
}

type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

func (s *Server) generateRegistrationToken(clientID string) string {
	mac := hmac.New(sha256.New, s.dcrSecret)
	mac.Write([]byte(clientID))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return clientID + "." + sig
}

func (s *Server) verifyRegistrationToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", errors.New("invalid token format")
	}
	clientID := parts[0]
	sig := parts[1]

	mac := hmac.New(sha256.New, s.dcrSecret)
	mac.Write([]byte(clientID))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return "", errors.New("invalid signature")
	}
	return clientID, nil
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeDCRError(w, "invalid_request", "Method must be POST", http.StatusMethodNotAllowed)
		return
	}

	var req dcrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeDCRError(w, "invalid_client_metadata", "Failed to parse JSON body", http.StatusBadRequest)
		return
	}

	// Validate Redirect URIs
	if len(req.RedirectURIs) == 0 {
		s.writeDCRError(w, "invalid_redirect_uri", "Missing redirect_uris", http.StatusBadRequest)
		return
	}

	for _, uriStr := range req.RedirectURIs {
		u, err := url.Parse(uriStr)
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			s.writeDCRError(w, "invalid_redirect_uri", "Invalid redirect URI: "+uriStr, http.StatusBadRequest)
			return
		}
	}

	// Determine token_endpoint_auth_method
	isPublic := false
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_post" // Default to client_secret_post or client_secret_basic
	} else if authMethod == "none" {
		isPublic = true
	} else if authMethod != "client_secret_post" && authMethod != "client_secret_basic" {
		s.writeDCRError(w, "invalid_client_metadata", "Unsupported token_endpoint_auth_method: "+authMethod, http.StatusBadRequest)
		return
	}

	// Default grant_types and response_types if omitted
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Validate requested grant_types and response_types are supported by the server
	for _, gt := range grantTypes {
		supported := false
		for _, sg := range s.supportedGrantTypes {
			if gt == sg {
				supported = true
				break
			}
		}
		if !supported {
			s.writeDCRError(w, "invalid_client_metadata", "Unsupported grant_type: "+gt, http.StatusBadRequest)
			return
		}
	}

	for _, rt := range responseTypes {
		if !s.supportedResponseTypes[rt] {
			s.writeDCRError(w, "invalid_client_metadata", "Unsupported response_type: "+rt, http.StatusBadRequest)
			return
		}
	}

	// Generate client ID and client secret (if not public)
	clientID := storage.NewID()
	clientSecret := ""
	if !isPublic {
		clientSecret = storage.NewID() + storage.NewID()
	}

	client := storage.Client{
		ID:           clientID,
		Secret:       clientSecret,
		RedirectURIs: req.RedirectURIs,
		Public:       isPublic,
		Name:         req.ClientName,
		LogoURL:      req.LogoURI,
	}

	// Save to storage
	if err := s.storage.CreateClient(r.Context(), client); err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to create client in storage", "err", err)
		s.writeDCRError(w, "server_error", "Failed to save client metadata", http.StatusInternalServerError)
		return
	}

	// Generate registration access token
	regToken := s.generateRegistrationToken(clientID)

	// Construct success response
	resp := dcrResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        s.now().Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              client.Name,
		ClientURI:               req.ClientURI,
		LogoURI:                 client.LogoURL,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TosURI:                  req.TosURI,
		PolicyURI:               req.PolicyURI,
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   s.absURL("/register/" + clientID),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.ErrorContext(r.Context(), "Failed to write DCR response", "err", err)
	}
}

func (s *Server) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["client_id"]
	if clientID == "" {
		s.writeDCRError(w, "invalid_request", "Missing client ID", http.StatusBadRequest)
		return
	}

	// Authenticate via registration access token
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		s.writeDCRError(w, "invalid_token", "Bearer token required", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(authHeader[len("bearer "):])

	tokenClientID, err := s.verifyRegistrationToken(token)
	if err != nil {
		s.writeDCRError(w, "invalid_token", "Invalid registration access token", http.StatusUnauthorized)
		return
	}

	if tokenClientID != clientID {
		s.writeDCRError(w, "invalid_token", "Token does not match client ID", http.StatusForbidden)
		return
	}

	// Retrieve client from storage
	client, err := s.storage.GetClient(r.Context(), clientID)
	if err != nil {
		if err == storage.ErrNotFound {
			s.writeDCRError(w, "invalid_token", "Client not found", http.StatusNotFound)
		} else {
			s.logger.ErrorContext(r.Context(), "Failed to get client from storage", "err", err)
			s.writeDCRError(w, "server_error", "Failed to retrieve client metadata", http.StatusInternalServerError)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Generate new registration token
		regToken := s.generateRegistrationToken(client.ID)

		authMethod := "client_secret_post"
		if client.Public {
			authMethod = "none"
		}

		resp := dcrResponse{
			ClientID:                client.ID,
			ClientSecret:            client.Secret,
			ClientIDIssuedAt:        s.now().Unix(),
			ClientSecretExpiresAt:   0,
			ClientName:              client.Name,
			LogoURI:                 client.LogoURL,
			RedirectURIs:            client.RedirectURIs,
			TokenEndpointAuthMethod: authMethod,
			RegistrationAccessToken: regToken,
			RegistrationClientURI:   s.absURL("/register/" + client.ID),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)

	case http.MethodDelete:
		if err := s.storage.DeleteClient(r.Context(), client.ID); err != nil {
			s.logger.ErrorContext(r.Context(), "Failed to delete client from storage", "err", err)
			s.writeDCRError(w, "server_error", "Failed to delete client", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		s.writeDCRError(w, "invalid_request", "Unsupported method: "+r.Method, http.StatusMethodNotAllowed)
	}
}

func (s *Server) writeDCRError(w http.ResponseWriter, errCode, errDesc string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	}
	_ = json.NewEncoder(w).Encode(resp)
}
