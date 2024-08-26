package hsdp

import (
	"encoding/json"
	"fmt"
	"strings"
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

	c.logger.Info("ExtendPayload called", "sub", cd.Introspect.Sub, "user", cd.Introspect.Username)

	// Check if we have a trusted org mapping
	aud := originalClaims["aud"].(string)
	if orgID, ok := c.audienceTrustMap[aud]; ok {
		c.logger.Info("Found trusted org mapping", "audience", aud, "org", orgID)
		trustedOrgID = orgID
	}

	// Service identities only support their managing org as the trusted org
	// and token should expire when the service identity token expires
	if cd.Introspect.IdentityType == "Service" {
		trustedOrgID = cd.Introspect.Organizations.ManagingOrganization
		originalClaims["exp"] = cd.Introspect.Expires
		originalClaims["username"] = cd.Introspect.Sub
		originalClaims["preferred_username"] = cd.Introspect.Sub
	}

	for _, scope := range scopes {
		// Experimental fill introspect body into claims
		if scope == "hsp:iam:introspect" {
			originalClaims["intr"] = cd.Introspect
		}
		// Experimental fill token into claims
		if scope == "hsp:iam:token" {
			originalClaims["tkn"] = string(cd.AccessToken)
		}
	}
	originalClaims["idt"] = cd.Introspect.IdentityType
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
			// Add roles
			originalClaims["roles"] = org.Roles
			// Add permissions
			originalClaims["permissions"] = org.Permissions
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
