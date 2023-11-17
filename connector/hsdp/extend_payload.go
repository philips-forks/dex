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

	trustedOrgID := c.trustedOrgID

	if err := json.Unmarshal(cdata, &cd); err != nil {
		return payload, err
	}
	if err := json.Unmarshal(payload, &originalClaims); err != nil {
		return payload, err
	}

	c.logger.Info("ExtendPayload called for user: %s", cd.Introspect.Username)

	for _, scope := range scopes {
		if scope == "federated:id" {
			originalClaims["iam_access_token"] = string(cd.AccessToken)
		}
		// Check if we should use the trusted_tenant scope
		if strings.HasPrefix(scope, "trusted_tenant:") {
			var tenant string
			if count, err := fmt.Sscanf(scope, "trusted_tenant:%s", &tenant); err == nil && count == 1 {
				trustedOrgID = tenant
			} else {
				c.logger.Errorf("error parsing scope: %s", scope)
			}
		}

		// Experimental fill introspect body into claims
		if scope == "hsp:iam:introspect" {
			originalClaims["introspect"] = cd.Introspect
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
	originalClaims["mid"] = cd.Introspect.Organizations.ManagingOrganization
	originalClaims["tid"] = trustedOrgID
	// Rewrite subject
	var orgSubs []string
	var orgGroups []string
	for _, org := range cd.Introspect.Organizations.OrganizationList {
		if org.OrganizationID == trustedOrgID { // Add groups from trusted IDP org
			orgGroups = org.Groups
			for _, group := range org.Groups {
				if strings.HasPrefix(group, "sub-") {
					orgSubs = append(orgSubs, fmt.Sprintf("sub:%s", strings.TrimPrefix(group, "sub-")))
				}
			}
		}
	}
	// Rewrite name
	if cd.User.GivenName != "" {
		originalClaims["name"] = fmt.Sprintf("%s %s", cd.User.GivenName, cd.User.FamilyName)
	}
	// Inject username
	if cd.Introspect.Username != "" {
		originalClaims["username"] = cd.Introspect.Username
		originalClaims["preferred_username"] = cd.Introspect.Username
	}
	if len(orgSubs) > 0 {
		subs := strings.Join(orgSubs, ":")
		origSub := originalClaims["sub"].(string)
		originalClaims["sub"] = fmt.Sprintf("%s:id:%s", subs, origSub)
	}
	if len(orgGroups) > 0 || trustedOrgID != cd.TrustedIDPOrg {
		originalClaims["groups"] = orgGroups
	}

	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}
