# HSP IAM connector

This connector allows you to use the HSP IAM service as an identity provider for your Cloud Foundry applications.

## Configuration

There are a few steps required to configure the HSP IAM Dex connector, specifically for CODE1 integration. In the below
example we'll assume you are going to install Dex on the following URL:

`https://dex.example.com`

### 1. Create HSP IAM OAuth2 OAuth2

Create an OAuth2 Client in your HSP IAM Organization. Set the `RedirectURI` to the Dex callback URL:

`https://dex.example.com/callback`

Add the following scopes, also include these as default scopes:
  - auth_iam_introspect
  - auth_iam_organization
  - openid
  - profile
  - email
  - name

The `ClientId` and `ClientSecret` are required in the config step below

### 2. Open a SNOW ticket to allow-list the Dex callback URL and to request the SAML2 login URL

Open a General service request in SNOW to allow-list the Dex callback URL. This is required to allow the Dex callback URL to be used in the HSP IAM service.
The RedirectURI pattern to allow-list should be this:

```https://dex.example.com/*?*```

Note the `*?*` at the end. This is required to allow the HSP IAM service to pass the OAuth2 code back to Dex.

In the same SNOW ticket also request the IAM team to share the `CODE1 SAML2 Login URL`. This URL is the value to use for saml2LoginURL in the config below.
It should look like something like this:

```https://iam-integration.iam-region.philips-healthsuite.com/authorize/saml2/login?idp_id=https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/&client_id=sp-philips-hspiam-region&api-version=1```

### 3. Create one or more static clients in Dex

Create one ore more static clients in Dex. These clients are used in your app
to integrated with Dex itself. Example:

```yaml
config:
  staticClients:
    - id: example-app
      secret: SecretHere
      name: 'Example App'
      # Where the app will be running.
      redirectURIs:
        - 'https://your-app.example.com/callback'
```

### 4. Create a hsdp connector in Dex

```yaml
config:
  connectors:
    - type: hsdp
      id: hsdp
      name: HSP IAM Code1
      config:
        trustedOrgID: 8a67a785-73bb-46d5-b73f-d951a6d3cb43
        audienceTrustMap:
          example-app: 8a67a785-73bb-46d5-b73f-d951a6d3cb43
        issuer: 'https://iam-client-test.us-east.philips-healthsuite.com/authorize/oauth2/v2'
        insecureIssuer: 'https://iam-client-test.us-east.philips-healthsuite.com/oauth2/access_token'
        saml2LoginURL: 'https://iam-integration.us-east.philips-healthsuite.com/authorize/saml2/login?idp_id=https://sts.windows.net/1a407a2d-7675-4d17-8692-b3ac285306e4/&client_id=sp-philips-hspiam-useast-ct&api-version=1'
        clientID: ClientId          # The OAuth2 Client ID from step 1
        clientSecret: ClientSecret  # The OAuth2 Client Secret from step 1
        iamURL: 'https://iam-client-test.us-east.philips-healthsuite.com'
        idmURL: 'https://idm-client-test.us-east.philips-healthsuite.com'
        redirectURI: https://dex.example.com/callback
        getUserInfo: true
        userNameKey: sub
        scopes:
          - auth_iam_introspect
          - auth_iam_organization
          - openid
          - profile
          - email
          - name
```

#### argument description

| Argument           | Type                                | Description                                                                                                                |
|--------------------|-------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| `trustedOrgID`     | string                              | The default HSP IAM Organization ID to trust. This is the Organization ID of the HSP IAM Org.                              |
| `audienceTrustMap` | map(string)                         | A mapping of static clients to trusted Organization ID. Use this to override the default `trustedOrgId` for a given client |
| `issuer`           | string                              | The HSP IAM OAuth2 issuer URL.                                                                                             |
| `insecureIssuer`   | string                              | The HSP IAM OAuth2 issuer URL for introspection.                                                                           |
| `saml2LoginURL`    | string                              | The HSP IAM SAML2 login URL.                                                                                               |
| `clientID`         | string                              | The OAuth2 Client ID from step 1.                                                                                          |
| `clientSecret`     | string                              | The OAuth2 Client Secret from step 1.                                                                                      |
| `iamURL`           | string                              | The HSP IAM URL.                                                                                                           |
| `idmURL`           | string                              | The HSP IDM URL.                                                                                                           |
| `redirectURI`      | string                              | The Dex redirect URI.                                                                                                      |
| `getUserInfo`      | bool                                | Whether to get user info.                                                                                                  |
| `userNameKey`      | bool                                | The key to use for the user name.                                                                                          |
| `scopes`           | list(string) The scopes to request. |


You are now set. Dex will integrate with HSP IAM Code1 and your apps can now
integrate with Dex through OIDC. All roles assigned in the trusted HSP IAM Org will
be exposed as `claims` to your app.

## Custom scopes

The connector supports custom scopes. To use them, you need to create a custom scope in the HSP IAM service and then add it to the `scopes` array in the `manifest.yml` file.

| Scope                | Description                                |
|----------------------|--------------------------------------------|
| `hsp:iam:introspect` | Returns introspect response as a claim.    |
| `hsp:iam:token`      | Returns a HSP IAM access token as a claim. |

> All the above-mentioned scopes are optional but must be specified in the `allowed_scopes` settings for them to become available.
