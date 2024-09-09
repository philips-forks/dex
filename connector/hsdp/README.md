# hsdp connector

This connector supports [HSP IAM](https://www.hsdp.io/documentation/identity-and-access-management-iam/getting-started) as an upstream IDP for Dex.

# helm chart

Dex is deployed using the [helm chart](https://artifacthub.io/packages/helm/dex/dex) from the [Artifact Hub](https://artifacthub.io/).

# configuration

When deploying Dex with the HSP IAM connector, you need to configure the connector in the Dex configuration file.
Helm chart users can configure the connector in the `values.yaml` file.

Connector section example:

```yaml
  connectors:
    - type: hsdp
      id: hsdp
      name: Philips Code1
      config:
        enableRoleClaim: true
        enableGroupClaim: false
        trustedOrgID: 8a67a785-73bb-46d5-b73f-d951a6d3cb43
        tenantMap:
          dae89cf0-888d-4a26-8c1d-578e97365efc: rpi5
          8a67a785-73bb-46d5-b73f-d951a6d3cb43: starlift
        issuer: 'https://iam-client-test.us-east.philips-healthsuite.com/authorize/oauth2/v2'
        insecureIssuer: 'https://iam-client-test.us-east.philips-healthsuite.com/oauth2/access_token'
        saml2LoginURL: 'https://iam-integration.us-east.philips-healthsuite.com/authorize/saml2/login?idp_id=https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/&client_id=sp-philips-hspiam-useast-ct&api-version=1'
        clientID: iamclient
        clientSecret: SecretHere
        iamURL: 'https://iam-client-test.us-east.philips-healthsuite.com'
        idmURL: 'https://idm-client-test.us-east.philips-healthsuite.com'
        redirectURI: https://dex.hsp.philips.com/callback
        getUserInfo: true
        userNameKey: sub
        scopes:
          - auth_iam_introspect
          - auth_iam_organization
          - openid
          - profile
          - email
          - name
          - federated:id
```

The following fields are supported:

| Config field     | Type        | Description                                                                |
|------------------|-------------|----------------------------------------------------------------------------|
| trustedOrgID     | string      | The HSP IAM OrgID to determine claims                                      |
| tenantMap        | map(string) | Mapping of OrgIDs to tenant IDs (Observability                             |
| issuer           | string      | The issuer URL of the HSP IAM deployment                                   |
| insecureIssuer   | string      | the issuer as returnd by HSP IAM. These are different in current IAM (bug) |
| saml2LoginURL    | string      | The SAML login URL given by HSP IAM for SSO login (code1)                  |
| clientID         | string      | An HSP IAM OAuth2 client ID                                                |
| clientSecret     | string      | An HSP IAM OAuth2 client secret                                            |
| redirectURI      | string      | The redirect URI of your Dex deployment. PAth should be `/callback`        |
| getUserInfo      | bool        | Wether to inject complete userInfo as a claim in the JWT Token             |
| userNameKey      | string      | The username key. Should be set to `sub`                                   |
| scopes           | string      | The scopes to send to HSP IAM                                              |
| enableGroupClaim | bool        | Enable group claim                                                         |
| enableRoleClaim  | bool        | Enable role claim                                                          |
