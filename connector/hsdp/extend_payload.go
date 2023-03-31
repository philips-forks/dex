package hsdp

import (
	"encoding/json"
	"strings"

	"github.com/dexidp/dex/connector"
)

var _ connector.PayloadExtender = (*hsdpConnector)(nil)

func (c *hsdpConnector) ExtendPayload(scopes []string, payload []byte, cdata []byte) ([]byte, error) {
	var cd connectorData
	var originalClaims map[string]interface{}

	c.logger.Info("ExtendPayload called")

	if err := json.Unmarshal(cdata, &cd); err != nil {
		return payload, err
	}
	if err := json.Unmarshal(payload, &originalClaims); err != nil {
		return payload, err
	}
	for _, scope := range scopes {
		if scope == "federated:id" {
			originalClaims["iam_access_token"] = string(cd.AccessToken)
		}
		if scope == "groups" {
			originalClaims["csgroups"] = strings.Join(cd.Groups, ",")
		}
	}
	originalClaims["moid"] = cd.Introspect.Organizations.ManagingOrganization

	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}
