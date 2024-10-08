package hsdp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func (c *HSDPConnector) ExtendPayload(scopes []string, payload []byte, cdata []byte) ([]byte, error) {
	var cd ConnectorData
	var originalClaims map[string]interface{}

	if err := json.Unmarshal(cdata, &cd); err != nil {
		return payload, err
	}
	if err := json.Unmarshal(payload, &originalClaims); err != nil {
		return payload, err
	}

	c.logger.Info("ExtendPayload called", "sub", cd.Introspect.Sub, "user", cd.Introspect.Username)

	// Service identity tokens should expire when the service identity token expires
	if cd.Introspect.IdentityType == "Service" {
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
	// Rewrite subject
	var orgSubs []string
	var orgGroups []string
	var orgRoles []string
	for _, org := range cd.Introspect.Organizations.OrganizationList {
		for _, role := range org.Roles {
			orgRoles = append(orgRoles, fmt.Sprintf("urn:iamr:%s:%s", org.OrganizationID, strings.ToLower(role)))
		}
		for _, group := range org.Groups {
			orgGroups = append(orgGroups, fmt.Sprintf("urn:iamg:%s:%s", org.OrganizationID, strings.ToLower(group)))
		}
	}
	if c.enableRoleClaim && len(orgRoles) > 0 {
		originalClaims["roles"] = orgRoles
	}
	if c.enableGroupClaim && len(orgGroups) > 0 {
		originalClaims["groups"] = orgGroups
	}
	if c.enableRoleClaim && c.roleAsGroupClaim && len(orgRoles) > 0 {
		originalClaims["groups"] = orgRoles
		delete(originalClaims, "roles")
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

	// Custom claims for Observability
	var readTenants []string
	// Collect all orgs for which the user has LOG.READ permission
	for _, org := range cd.Introspect.Organizations.OrganizationList {
		if slices.Contains(org.Permissions, "LOG.READ") {
			readTenants = append(readTenants, mapper(org.OrganizationID, c.tenantMap))
		}
	}
	if len(readTenants) > 0 {
		originalClaims["ort"] = readTenants
	}
	extendedPayload, err := json.Marshal(originalClaims)
	if err != nil {
		return payload, err
	}
	return extendedPayload, nil
}

func mapper(src string, data map[string]string) string {
	if orgID, ok := data[src]; ok {
		return orgID
	}
	return src
}
