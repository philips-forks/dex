package hsdp

import (
	"encoding/json"
	"github.com/dexidp/dex/connector"
)

type idTokenClaims struct {
	Issuer           string   `json:"iss"`
	Subject          string   `json:"sub"`
	Audience         []string `json:"aud"`
	Expiry           int64    `json:"exp"`
	IssuedAt         int64    `json:"iat"`
	AuthorizingParty string   `json:"azp,omitempty"`
	Nonce            string   `json:"nonce,omitempty"`

	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`

	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`

	Groups []string `json:"groups,omitempty"`

	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`

	FederatedIDClaims json.RawMessage `json:"federated_claims,omitempty"`
}

type extendedIdTokenClaims struct {
	idTokenClaims
	Extended bool `json:"extended,omitempty"`
}

var (
	_ connector.PayloadExtender = (*hsdpConnector)(nil)
)

func (c *hsdpConnector) ExtendPayload(payload []byte, connectorData []byte) ([]byte, error) {
	c.logger.Info("ExtendPayload was called")
	var ext extendedIdTokenClaims
	err := json.Unmarshal(payload, &ext)
	if err != nil {
		return payload, err
	}
	ext.Extended = true
	extendedPayload, err := json.Marshal(ext)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}
