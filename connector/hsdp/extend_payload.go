package hsdp

import (
	"encoding/json"
	"github.com/dexidp/dex/connector"
)

var (
	_ connector.PayloadExtender = (*hsdpConnector)(nil)
)

func (c *hsdpConnector) ExtendPayload(payload []byte, cdata []byte) ([]byte, error) {
	var cd connectorData
	var originalClaims map[string]interface{}

	c.logger.Info("ExtendPayload called")

	if err := json.Unmarshal(cdata, &cd); err != nil {
		return payload, err
	}
	if err := json.Unmarshal(payload, &originalClaims); err != nil {
		return payload, err
	}
	originalClaims["extended"] = true
	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}
