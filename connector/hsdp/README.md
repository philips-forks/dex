# hsdp connector

This connector supports [HSP IAM](https://www.hsdp.io/documentation/identity-and-access-management-iam/getting-started) as an upstream IDP for Dex.

# helm chart

Dex is deployed using the [helm chart](https://artifacthub.io/packages/helm/dex/dex) from the [Artifact Hub](https://artifacthub.io/).

# configuration

When deploying Dex with the HSP IAM connector, you need to configure the connector in the Dex configuration file.
Helm chart users can configure the connector in the `values.yaml` file.

OAuth2 authorization code logins use PKCE with the S256 code challenge method automatically.
The SAML assertion flow is unaffected.

Connector section example:

```yaml
  connectors:
    - type: hsdp
      id: hsdp
      name: Philips Code1
      config:
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

| Config field   | Type        | Description                                                                |
|----------------|-------------|----------------------------------------------------------------------------|
| trustedOrgID   | string      | The HSP IAM OrgID to determine claims                                      |
| tenantMap      | map(string) | Mapping of OrgIDs to tenant IDs (Observability                             |
| issuer         | string      | The issuer URL of the HSP IAM deployment                                   |
| insecureIssuer | string      | the issuer as returnd by HSP IAM. These are different in current IAM (bug) |
| saml2LoginURL  | string      | The SAML login URL given by HSP IAM for SSO login (code1)                  |
| clientID       | string      | An HSP IAM OAuth2 client ID                                                |
| clientSecret   | string      | An HSP IAM OAuth2 client secret                                            |
| redirectURI    | string      | The redirect URI of your Dex deployment. PAth should be `/callback`        |
| getUserInfo    | bool        | Wether to inject complete userInfo as a claim in the JWT Token             |
| userNameKey    | string      | The username key. Should be set to `sub`                                   |
| scopes         | string      | The scopes to send to HSP IAM                                              |
| idpHint        | string      | IAM identity provider alias sent as `kc_idp_hint`, skipping the IAM login page (see below) |
| addGroups      | []string    | Groups always added to every user's groups, e.g. to identify users of this connector (see below) |

## Skipping the HSP IAM login page (`idpHint`)

By default an OAuth2 login lands on the HSP IAM login page, where users can
either sign in with an IAM username/password or enter their domain under
"Continue with SSO". To always use one federated identity provider (e.g. the
philips.com Entra ID SSO, "Philips CODE1"), set `idpHint`. The connector sends
it as the `kc_idp_hint` parameter on the authorization request, and IAM
redirects straight to that identity provider without showing its own page.

```yaml
  connectors:
    - type: hsdp
      id: code1
      name: Philips CODE1
      config:
        issuer: 'https://iam-service.eu-west.philips-healthsuite.com/authorize/oauth2/v2'
        insecureIssuer: 'https://auth.eu1.iam.hsp.philips.com/realms/healthsuite'
        clientID: publicdipservices   # public client: no clientSecret, PKCE only
        redirectURI: https://dex.example.com/callback
        iamURL: 'https://iam-service.eu-west.philips-healthsuite.com'
        idmURL: 'https://idm-service.eu-west.philips-healthsuite.com'
        scopes:
          - auth_iam_introspect
          - auth_iam_organization
          - profile
          - email
        idpHint: sp-philips-hspiam-euwest_idpAlias
        enableRoleClaim: true
        roleAsGroupClaim: true
```

Notes:

- **Finding the alias**: the value is IAM's identity provider alias, not a
  domain. Submit the "Continue with SSO" form on the IAM login page with your
  domain (e.g. `philips.com`); IAM redirects to
  `.../realms/healthsuite/broker/<alias>/login`, and `<alias>` is the value to
  use. For philips.com on eu-west production it is
  `sp-philips-hspiam-euwest_idpAlias`.
- **`idpHint` vs `saml2LoginURL`**: on the current (Keycloak-based) HSP IAM,
  the `saml2/login` URL just redirects to the OAuth2 authorize endpoint with
  `kc_idp_hint=<client_id>_idpAlias`, under that SAML service provider's own
  client. That means the Dex callback must be registered on the SP's client and
  the code is issued to it, not to your OAuth2 client, so it does not work for
  a regular Dex connector client. `idpHint` uses the same mechanism but keeps
  the normal OAuth2 + PKCE flow under your own `clientID`.
- `idpHint` only affects the OAuth2 authorization code flow; it is ignored
  when `saml2LoginURL` is set.
- If the alias is unknown to IAM, the authorize request fails with an error
  page instead of falling back to the IAM login page.

## Tagging users of this connector (`addGroups`)

`addGroups` adds a fixed list of groups to every user who logs in through this
connector. Use it when downstream apps need to tell which connector (and so
which customer or IAM deployment) a user came from, using only the `groups`
claim:

```yaml
connectors:
  - type: hsdp
    id: hsdp-customer-a
    name: Customer A
    config:
      # ...
      addGroups:
        - customer:customer-a
```

- The groups are added to the user's Dex identity at login, refresh and token
  exchange, so per-client `allowedGroups` checks can match on them.
- They are always in the token's `groups` claim, merged with whatever
  `enableGroupClaim`, `enableRoleClaim`/`roleAsGroupClaim` produce, even when
  the client did not request the `groups` scope.
- Empty entries and duplicates are dropped.

