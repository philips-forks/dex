package hsdp

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

func (c *HSDPConnector) ExtendPayload(scopes []string, payload []byte, cdata []byte) ([]byte, error) {
	var cd ConnectorData
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
		// Experimental tenant scoping
		if strings.HasPrefix(scope, "tenant:") {
			group := strings.TrimPrefix(scope, "tenant:")
			if slices.Contains(c.tenantGroups, group) {
				var tenants []string
				// Iterate through introspect and add OrgID as tenant when matched
				for _, org := range cd.Introspect.Organizations.OrganizationList {
					for _, orgGroup := range org.Groups {
						if group == orgGroup {
							tenants = append(tenants, org.OrganizationID)
						}
					}
				}
				if len(tenants) > 0 {
					originalClaims[scope] = tenants
				}
			}
		}
	}
	originalClaims["moid"] = cd.Introspect.Organizations.ManagingOrganization
	// Rewrite subject
	var orgSubs []string
	for _, org := range cd.Introspect.Organizations.OrganizationList {
		if org.OrganizationID != cd.TrustedIDPOrg {
			continue
		}
		for _, group := range org.Groups {
			if strings.HasPrefix(group, "sub-") {
				orgSubs = append(orgSubs, fmt.Sprintf("sub:%s", strings.TrimPrefix(group, "sub-")))
			}
		}
	}
	// Rewrite name
	if cd.User.Name.Given != "" {
		originalClaims["name"] = fmt.Sprintf("%s %s", cd.User.Name.Given, cd.User.Name.Family)
	}
	if len(orgSubs) > 0 {
		subs := strings.Join(orgSubs, ":")
		origSub := originalClaims["sub"].(string)
		originalClaims["sub"] = fmt.Sprintf("%s:id:%s", subs, origSub)
	}

	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}
