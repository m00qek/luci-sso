# UCI Configuration Reference

The configuration for `luci-sso` is stored in `/etc/config/luci-sso`. It holds one `config oidc 'default'` section, which connects the router to the IdP (identity provider, the OIDC service that signs users in), and one or more `config role` sections, which decide who may log in and with what rights.

Edit it with `uci`, or through the LuCI settings page described in [LuCI Form ↔ UCI Option](#luci-form-uci-option). A complete file is shown in [Example Configuration](#example-configuration).

---

## OIDC Section (`config oidc 'default'`)

The connection to the IdP. A missing or invalid required option makes every request fail with `CONFIG_ERROR` while SSO is enabled.

| Option | Type | Description |
| :--- | :--- | :--- |
| `enabled` | boolean | Must be set to `1` to activate the service. |
| `issuer_url` | string (URL) | Required. The logical OIDC issuer identifier. Must use `https://`. Used for `iss` claim validation and as the base URL for OIDC discovery. See [notes](#oidc-section-notes). |
| `internal_issuer_url` | string (URL) | Optional. The origin (`https://host[:port]`, no path; a single trailing `/` is accepted) the router uses for back-channel HTTP requests in place of `issuer_url`'s origin. See [notes](#oidc-section-notes). |
| `client_id` | string | Required. The Client ID registered with your IdP. |
| `client_secret` | string | Required. The Client Secret registered with your IdP. Stored in plain text in `/etc/config/luci-sso` — restrict shell and physical access to the router accordingly. |
| `redirect_uri` | string (URL) | The callback URL registered with the IdP: `https://<router-host>/cgi-bin/luci-sso/callback`. Must use `https://` and exactly match what the IdP client is configured to accept. Unset in the shipped configuration; the LuCI settings page then suggests one from the browser's host name, without port. Enabling SSO without it fails with `CONFIG_ERROR` (`redirect_uri is mandatory and must use HTTPS`). |
| `scope` | string | Optional. Space-separated list of OIDC scopes to request. Default: `openid profile email`. Add `groups` if the IdP supports group claims and role mapping by group is required. |
| `clock_tolerance` | integer | Required. Allowed clock skew in seconds applied to JWT `exp` and `iat` validation. Valid range: `0`–`3600`. See [notes](#oidc-section-notes). |

### OIDC section notes

- **`issuer_url`** must match the `issuer` value the IdP declares in its discovery document. The comparison ignores a trailing slash, the letter case of scheme and host, and an explicit `:443`.
- **`internal_issuer_url`** applies to the router's back-channel HTTP requests: discovery, token exchange, JWKS fetch and UserInfo.
    - Back-channel URLs on `issuer_url`'s origin get this origin instead. Their paths are kept. With `issuer_url` `https://kc.example.com/realms/home` and `internal_issuer_url` `https://10.0.0.5:8443`, discovery is fetched from `https://10.0.0.5:8443/realms/home/.well-known/openid-configuration`.
    - A value that does not use `https://`, or has a path, query or fragment, is rejected with `CONFIG_ERROR`.
    - The `iss` claim is still validated against `issuer_url`.
    - See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md).
- **`clock_tolerance`** has no built-in code default: if it is absent, the service reports `CONFIG_ERROR`. The shipped UCI configuration sets it to `60`.

---

## Role Mapping (`config role`)

Each `config role` section grants LuCI rights to the users it matches. A user is assigned a role if ANY of its conditions match (OR logic). Multiple roles may match; permissions are merged.

`read` and `write` name LuCI **access groups**: the top-level keys of the JSON files in `/usr/share/rpcd/acl.d/`, such as `luci-mod-status-realtime`. `rpcd` is the OpenWrt daemon that holds LuCI sessions and their permissions.

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC `email` claim. Case-insensitive. |
| `group` | list (string) | Match by a value of the OIDC `groups` claim, which must be a JSON array. Case-sensitive. For Pocket ID, include the `@PocketID` suffix. |
| `read` | list (string) | Access groups granted read access. `*` means read on every `luci-*` group, and nothing more. |
| `write` | list (string) | Access groups granted write access; write implies read. `*` makes the role a full admin (see [notes](#role-mapping-notes)). |

### Role mapping notes

- **Group expansion.** Each group in `read` or `write` is expanded into the permissions its ACL file lists, as rpcd does for a password login. Globs and `!negations` work as in rpcd.
- **Saving settings.** Saving anything also needs `luci-base` in `write`, whose write section holds `uci set` and `uci apply`.
- **Full admin.** `write '*'` grants read and write on every group, plus unrestricted `ubus`, `uci`, `file` and `cgi-io` access.
- **No rights.** A user who matches roles that have no `read` or `write` entries at all is refused with `USER_NOT_AUTHORIZED`.
- **Invalid roles.** A role that has neither an `email` nor a `group` entry is ignored, and the log says `Ignoring role '<name>': missing email or group list`. If no valid role is left, the service reports `CONFIG_ERROR` (`No valid roles found in /etc/config/luci-sso`).

For worked examples, see [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md).

---

## LuCI Form ↔ UCI Option

The settings page at **Services > Single Sign-On** (view `services/sso`, heading **SSO Login**) edits `/etc/config/luci-sso`. Opening it needs the `luci-app-sso` access group. **Save & Apply** writes the form with `uci`; **Reset** reloads the last saved values without writing.

### Settings section

Edits `config oidc 'default'`.

| Field | UCI option | Form behaviour |
| :--- | :--- | :--- |
| **Enable SSO** | `enabled` | Checkbox; saved as `1` or `0`. While `0`, the login page shows no SSO button, the `?action=enabled` probe answers `{"enabled": false}`, and other requests to `/cgi-bin/luci-sso` get an error page (`SSO_DISABLED`). Password login is unaffected. |
| **Issuer URL** | `issuer_url` | Required. Rejects a value that does not start with `https://` (`Must use HTTPS`). Placeholder: `https://accounts.google.com`. |
| **Client ID** | `client_id` | Required. |
| **Client Secret** | `client_secret` | Required. Masked password field. |
| **Redirect URI** | `redirect_uri` | Required; must start with `https://`. When the option is unset, the field shows `https://<browser host>/cgi-bin/luci-sso/callback`, built from the host name in the browser's address bar without its port; when it is set, the saved value. |
| **Scopes** | `scope` | Optional. Placeholder: `openid profile email`, which is also what the login requests when the option is empty. |
| **Clock Tolerance** | `clock_tolerance` | Required integer, `0`–`3600`. Form default: `60`. |
| **Internal Issuer URL** | `internal_issuer_url` | Optional; must start with `https://`. Placeholder: `https://<browser host>:8443`. The form does not check that the value is an origin with no path; a path is rejected at login with `CONFIG_ERROR`. |

### Users section

Each row is a `config role '<name>'` section. **Add** takes the role name, which becomes the section name; the name `default` is refused, because it belongs to the OIDC section. The table's **Emails**, **Groups**, **Read Access** and **Write Access** columns list the role's values, or `(none)`. Each row's **Edit** button opens the role's editor; its **Delete** button deletes the section.

| Field (role editor) | UCI option | Form behaviour |
| :--- | :--- | :--- |
| **Email Addresses** | `email` | List; one address per entry. |
| **Groups** | `group` | List; one group per entry. |
| **Read Access** | `read` | List of access groups. |
| **Write Access** | `write` | List of access groups. |

Matching and permission rules for these options are in [Role Mapping](#role-mapping-config-role).

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
