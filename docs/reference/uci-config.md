# UCI Configuration Reference

The configuration for `luci-sso` is stored in `/etc/config/luci-sso`.

---

## OIDC Section (`config oidc 'default'`)

| Option | Type | Description |
| :--- | :--- | :--- |
| `enabled` | boolean | Must be set to `1` to activate the service. |
| `issuer_url` | string (URL) | The logical OIDC issuer identifier. Must use `https://`. Used for `iss` claim validation and as the base URL for OIDC discovery. Must exactly match the `issuer` value the IdP declares in its discovery document. |
| `internal_issuer_url` | string (URL) | (Optional) The physical URL the router uses for back-channel HTTP requests (discovery, token exchange, JWKS fetch, UserInfo). When set, the origin of every back-channel URL is replaced with this value; paths are preserved unchanged. The `iss` claim is still validated against `issuer_url`. Use when the router cannot reach the IdP at its public address. See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md). |
| `client_id` | string | The Client ID registered with your IdP. |
| `client_secret` | string | The Client Secret registered with your IdP. |
| `redirect_uri` | string (URL) | The callback URL registered with the IdP. Must use `https://` and exactly match what the IdP client is configured to accept. |
| `scope` | string | (Optional) Space-separated list of OIDC scopes to request. Default: `openid profile email`. Add `groups` if the IdP supports group claims and role mapping by group is required. |
| `clock_tolerance` | integer | Allowed clock skew in seconds applied to JWT `exp` and `iat` validation. Valid range: `0`–`3600`. The option has no built-in code default — if absent, the service reports `CONFIG_ERROR`. The shipped UCI configuration sets this to `60`. |

---

## Role Mapping (`config role`)

A user is assigned a role if ANY of its conditions match (OR logic). Multiple roles may match; permissions are merged.

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC `email` claim. Case-insensitive. |
| `group` | list (string) | Match by OIDC `groups` claim value. Case-sensitive. For Pocket ID, include the `@PocketID` suffix. |
| `read` | list (string) | LuCI access groups granted read access. Use `*` for all current and future groups. |
| `write` | list (string) | LuCI access groups granted write access. Use `*` for all current and future groups. |

---

## Example Configuration

```properties
config oidc 'default'
    option enabled '1'
    option issuer_url 'https://auth.example.com/realms/homelab'
    option client_id 'luci-router'
    option client_secret 'YOUR_SECRET_HERE'
    option redirect_uri 'https://192.168.1.1/cgi-bin/luci-sso/callback'
    option scope 'openid profile email'
    option clock_tolerance '60'

config role 'admin'
    list email 'admin@example.com'
    list group 'admins'
    list read '*'
    list write '*'
```
