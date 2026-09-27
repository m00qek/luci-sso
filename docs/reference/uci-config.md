# UCI Configuration Reference

The configuration for `luci-sso` is stored in `/etc/config/luci-sso`.

---

## OIDC Section (`config oidc 'default'`)

| Option | Type | Description |
| :--- | :--- | :--- |
| `enabled` | boolean | Must be set to `1` to activate the service. |
| `issuer_url` | string (URL) | The logical OIDC issuer identifier. Must use `https://`. Used for `iss` claim validation and as the base URL for OIDC discovery. Must exactly match the `issuer` value the IdP declares in its discovery document. |
| `internal_issuer_url` | string (URL) | (Optional) The origin (`https://host[:port]`, no path) the router uses for back-channel HTTP requests (discovery, token exchange, JWKS fetch, UserInfo). Back-channel URLs on `issuer_url`'s origin get this origin instead; their paths are kept, so with `issuer_url` `https://kc.example.com/realms/home` and `internal_issuer_url` `https://10.0.0.5:8443`, discovery is fetched from `https://10.0.0.5:8443/realms/home/.well-known/openid-configuration`. A path, query or fragment is rejected with `CONFIG_ERROR`. The `iss` claim is still validated against `issuer_url`. See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md). |
| `client_id` | string | The Client ID registered with your IdP. |
| `client_secret` | string | The Client Secret registered with your IdP. Stored in plain text in `/etc/config/luci-sso` — restrict shell and physical access to the router accordingly. |
| `redirect_uri` | string (URL) | The callback URL registered with the IdP: `https://<router-host>/cgi-bin/luci-sso/callback`. Must use `https://` and exactly match what the IdP client is configured to accept. Unset in the shipped configuration; the LuCI settings page then suggests one from the browser's host name. Enabling SSO without it fails with `CONFIG_ERROR` (`redirect_uri is mandatory and must use HTTPS`). |
| `scope` | string | (Optional) Space-separated list of OIDC scopes to request. Default: `openid profile email`. Add `groups` if the IdP supports group claims and role mapping by group is required. |
| `clock_tolerance` | integer | Allowed clock skew in seconds applied to JWT `exp` and `iat` validation. Valid range: `0`–`3600`. The option has no built-in code default — if absent, the service reports `CONFIG_ERROR`. The shipped UCI configuration sets this to `60`. |

---

## Role Mapping (`config role`)

A user is assigned a role if ANY of its conditions match (OR logic). Multiple roles may match; permissions are merged.

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC `email` claim. Case-insensitive. |
| `group` | list (string) | Match by OIDC `groups` claim value. Case-sensitive. For Pocket ID, include the `@PocketID` suffix. |
| `read` | list (string) | LuCI access groups (keys in `/usr/share/rpcd/acl.d/*.json`, e.g. `luci-mod-status-realtime`) granted read access. Globs and `!negations` work as in rpcd. `*` means read on every `luci-*` group, and nothing more. Each group is expanded into the permissions its ACL file lists, as rpcd does for a password login. |
| `write` | list (string) | LuCI access groups granted write access; write implies read. Saving anything also needs `luci-base`, whose write section holds `uci set` and `uci apply`. `*` makes the role a full admin: read and write on every group, plus unrestricted `ubus`, `uci`, `file` and `cgi-io` access. |

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
