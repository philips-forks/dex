# HSP IAM connector

This connector allows you to use the HSP IAM service as an identity provider for your Cloud Foundry applications.

## Custom scopes

The connector supports custom scopes. To use them, you need to create a custom scope in the HSP IAM service and then add it to the `scopes` array in the `manifest.yml` file.

| Scope                | Description                                |
|----------------------|--------------------------------------------|
| `hsp:iam:introspect` | Returns introspect response as a claim.    |
| `hsp:iam:token`      | Returns a HSP IAM access token as a claim. |

> All of the above mentioned scopes are optional but must be specified in the `allowed_scopes` settings for them to become available.
