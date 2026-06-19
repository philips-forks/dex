package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dexidp/dex/storage"
)

// unverifiedJWTIssuer extracts the "iss" claim from a compact JWT WITHOUT
// verifying its signature. It is used only to select which trusted-issuer
// verifier to apply; the selected verifier then fully validates the token.
func unverifiedJWTIssuer(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("could not decode JWT payload: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("could not parse JWT payload: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("JWT has no iss claim")
	}
	return claims.Issuer, nil
}

// newResourceAccessToken issues a Dex-signed access token whose audience is the
// given MCP server resource identifier rather than the requesting client. This
// satisfies the EMA §5.1 requirement that the access token be audience-restricted
// to the MCP server identified by the ID-JAG resource claim.
func (s *Server) newResourceAccessToken(ctx context.Context, clientID, resource string, claims storage.Claims) (string, time.Time, error) {
	issuedAt := s.now()
	expiry := issuedAt.Add(s.idTokensValidFor)

	tok := idTokenClaims{
		Issuer:           s.issuerURL.String(),
		Subject:          claims.UserID,
		Audience:         audience{resource},
		AuthorizingParty: clientID,
		Expiry:           expiry.Unix(),
		IssuedAt:         issuedAt.Unix(),
		JWTID:            storage.NewID(),
	}

	// The linked email comes from the ID-JAG identity (not a userinfo scope), so
	// it is carried whenever account linking populated it, regardless of scope.
	if claims.Email != "" {
		tok.Email = claims.Email
		ev := claims.EmailVerified
		tok.EmailVerified = &ev
	}

	payload, err := json.Marshal(tok)
	if err != nil {
		return "", expiry, fmt.Errorf("could not serialize access token claims: %w", err)
	}
	token, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return "", expiry, fmt.Errorf("failed to sign access token: %w", err)
	}
	return token, expiry, nil
}

// idJAGVerifier validates ID-JAG tokens minted by one trusted enterprise IdP.
// It wraps an oidc.IDTokenVerifier backed by the IdP's remote JWKS and carries
// the EMA policy (expected audience, allowed client IDs) for that issuer.
type idJAGVerifier struct {
	issuer           string
	expectedAudience string
	allowedClientIDs []string
	verifier         *oidc.IDTokenVerifier
}

// newIDJAGVerifiers builds a verifier per trusted issuer. The ExpectedAudience
// defaults to this Dex's own issuer URL when not set, per EMA §4 (the ID-JAG
// audience is the MCP Authorization Server's issuer identifier).
func newIDJAGVerifiers(ctx context.Context, issuerURL url.URL, trusted []TrustedIssuer) (map[string]*idJAGVerifier, error) {
	if len(trusted) == 0 {
		return nil, fmt.Errorf("enterpriseManagedAuthorization is enabled but no trustedIssuers are configured")
	}

	verifiers := make(map[string]*idJAGVerifier, len(trusted))
	for _, ti := range trusted {
		if ti.Issuer == "" {
			return nil, fmt.Errorf("trusted issuer is missing required field issuer")
		}
		if ti.JWKSURL == "" {
			return nil, fmt.Errorf("trusted issuer %q is missing required field jwksURL", ti.Issuer)
		}
		if _, exists := verifiers[ti.Issuer]; exists {
			return nil, fmt.Errorf("duplicate trusted issuer %q", ti.Issuer)
		}

		expectedAudience := ti.ExpectedAudience
		if expectedAudience == "" {
			expectedAudience = issuerURL.String()
		}

		keySet := oidc.NewRemoteKeySet(ctx, ti.JWKSURL)
		// The audience is enforced explicitly in verifyIDJAG so we can map the
		// failure to a precise error; skip the library's client-id check here.
		v := oidc.NewVerifier(ti.Issuer, keySet, &oidc.Config{SkipClientIDCheck: true})

		verifiers[ti.Issuer] = &idJAGVerifier{
			issuer:           ti.Issuer,
			expectedAudience: expectedAudience,
			allowedClientIDs: ti.AllowedClientIDs,
			verifier:         v,
		}
	}
	return verifiers, nil
}

// idJAGAssertion is the subset of ID-JAG claims Dex consumes as an MCP
// Authorization Server. See draft-ietf-oauth-identity-assertion-authz-grant §3.1.
type idJAGAssertion struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
	Resource string `json:"resource"`
	Scope    string `json:"scope"`
}

// handleJWTBearerGrant implements EMA Role B: an MCP Client redeems an ID-JAG
// (carried as the jwt-bearer "assertion") for an MCP access token. The issued
// access token is audience-restricted to the MCP server named by the ID-JAG
// "resource" claim (EMA §5.1).
func (s *Server) handleJWTBearerGrant(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()

	if !s.enableEMA {
		s.tokenErrHelper(w, errUnsupportedGrantType, "jwt-bearer grant is not enabled on this server.", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		s.tokenErrHelper(w, errInvalidRequest, "Could not parse request body.", http.StatusBadRequest)
		return
	}

	assertion := r.Form.Get("assertion")
	if assertion == "" {
		s.tokenErrHelper(w, errInvalidRequest, "Missing required parameter assertion.", http.StatusBadRequest)
		return
	}

	idjag, err := s.verifyIDJAG(ctx, assertion)
	if err != nil {
		s.logger.WarnContext(ctx, "ID-JAG assertion rejected", "client_id", client.ID, "err", err)
		s.tokenErrHelper(w, errInvalidGrant, "Invalid ID-JAG assertion.", http.StatusBadRequest)
		return
	}

	// EMA §5.1: the issued access token MUST be audience-restricted to the MCP
	// server identified by the resource claim. Without a resource, there is no
	// well-defined audience to bind to, so the request is rejected.
	if idjag.Resource == "" {
		s.tokenErrHelper(w, errInvalidGrant, "ID-JAG is missing the resource claim required to bind the access token audience.", http.StatusBadRequest)
		return
	}

	claims := storage.Claims{
		UserID: idjag.Subject,
	}
	if s.emaAccountLinking {
		claims.Email = idjag.Email
		claims.EmailVerified = idjag.Email != ""
	}

	accessToken, expiry, err := s.newResourceAccessToken(ctx, client.ID, idjag.Resource, claims)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to issue MCP access token from ID-JAG", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	s.logger.InfoContext(ctx, "MCP access token issued from ID-JAG",
		"client_id", client.ID,
		"sub", idjag.Subject,
		"resource", idjag.Resource,
		"id_jag_client_id", idjag.ClientID,
		"scope", idjag.Scope,
	)

	resp := accessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   int(time.Until(expiry).Seconds()),
		Scope:       idjag.Scope,
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// verifyIDJAG validates an ID-JAG against the configured trusted issuers and
// returns the consumed claims. It enforces the typ header, a trusted issuer,
// the expected audience, and (if configured) the allowed client_id.
func (s *Server) verifyIDJAG(ctx context.Context, assertion string) (*idJAGAssertion, error) {
	// Peek at the issuer (unverified) to select the right verifier. The
	// signature, issuer, expiry, and audience are all checked below.
	iss, err := unverifiedJWTIssuer(assertion)
	if err != nil {
		return nil, fmt.Errorf("could not read issuer: %w", err)
	}

	v, ok := s.idJAGVerifiers[iss]
	if !ok {
		return nil, fmt.Errorf("issuer %q is not a trusted issuer", iss)
	}

	tok, err := v.verifier.Verify(ctx, assertion)
	if err != nil {
		return nil, fmt.Errorf("signature/issuer/expiry verification failed: %w", err)
	}

	// EMA §4: the audience MUST be this MCP Authorization Server's issuer.
	if !slices.Contains(tok.Audience, v.expectedAudience) {
		return nil, fmt.Errorf("audience %v does not include expected audience %q", tok.Audience, v.expectedAudience)
	}

	var claims idJAGAssertion
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("could not parse ID-JAG claims: %w", err)
	}

	if len(v.allowedClientIDs) > 0 && !slices.Contains(v.allowedClientIDs, claims.ClientID) {
		return nil, fmt.Errorf("ID-JAG client_id %q is not allowed for issuer %q", claims.ClientID, iss)
	}

	return &claims, nil
}
