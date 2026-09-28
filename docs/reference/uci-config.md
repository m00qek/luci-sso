# UCI Configuration Reference

The configuration for `luci-sso` is stored in `/etc/config/luci-sso`. It holds one `config oidc 'default'` section, which connects the router to the IdP (identity provider, the OIDC service that signs users in), and one or more `config role` sections, which decide who may log in. Each role's rights are its login entry in `/etc/config/rpcd`.

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
| `require_email_verified` | boolean | Optional. Default: `1`, also when the option is absent. While on, an `email` rule matches only if the IdP's `email_verified` claim is the JSON boolean `true`. `0`, `no`, `off` or `false` turns it off. See [notes](#oidc-section-notes). |
| `clock_tolerance` | integer | Required. Allowed clock skew in seconds, applied to the ID Token's `exp`, `iat` and `nbf` checks and to the login handshake's expiry. Valid range: `0`–`3600`. See [notes](#oidc-section-notes). |

### OIDC section notes

- **`issuer_url`** must match the `issuer` value the IdP declares in its discovery document. The comparison ignores a trailing slash, the letter case of scheme and host, and an explicit `:443`.
- **`internal_issuer_url`** applies to the router's back-channel HTTP requests: discovery, token exchange, JWKS fetch and UserInfo.
    - Back-channel URLs on `issuer_url`'s origin get this origin instead. Their paths are kept. With `issuer_url` `https://kc.example.com/realms/home` and `internal_issuer_url` `https://10.0.0.5:8443`, discovery is fetched from `https://10.0.0.5:8443/realms/home/.well-known/openid-configuration`.
    - A value that does not use `https://`, or has a path, query or fragment, is rejected with `CONFIG_ERROR`.
    - The `iss` claim is still validated against `issuer_url`.
    - See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md).
- **`require_email_verified`** affects role matching only.
    - The claim is read from the response the email came from: the ID Token, or UserInfo when the ID Token has no `email`. The two are never mixed.
    - Only the JSON boolean `true` counts, as OIDC Core §5.1 defines the claim. Any other value, including the string `"true"`, or no claim, is not verified.
    - An unverified email is ignored for matching, and the log says `Ignoring the unverified email of user [sub_id: …] for role matching: email_verified is not true (require_email_verified)`. `group` rules still match. A user who matches no role is refused with `USER_NOT_AUTHORIZED`.
    - The email is still stored in the session as `oidc_user`.
    - What each IdP sends: [Provider Compatibility](provider-compatibility.md#verified-email). Why: [About Roles and Permissions](../explanation/roles-and-permissions.md#verified-email-addresses).
- **`clock_tolerance`** has no built-in code default: if it is absent, the service reports `CONFIG_ERROR`. The shipped UCI configuration sets it to `60`.

---

## Role Mapping (`config role`)

Each `config role '<name>'` section says which users get the role. What the role grants is its `rpcd` login entry, described in [Role Permissions (rpcd login entry)](#role-permissions-rpcd-login-entry). `rpcd` is the OpenWrt daemon that holds LuCI sessions and their rights.

A role matches a user if ANY of its `email` or `group` values matches. Roles are tried in the order of their sections in `/etc/config/luci-sso`; the user gets the **first** role that matches, and only that one.

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC `email` claim, ignoring letter case in the whole address. Only a verified email matches while `require_email_verified` is on (the default). See [notes](#role-mapping-notes). |
| `group` | list (string) | Match by a value of the OIDC `groups` claim, which must be a JSON array. Case-sensitive. |

### Role mapping notes

- **Section name.** The role's name. `default` is taken by the OIDC section. The role's `rpcd` entry needs a name of 1–32 letters, digits and underscores; a role with a longer name can exist in UCI, but it cannot get permissions, and its users cannot log in.
- **Email case.** `Alice@Example.com` and `alice@example.com` match the same rule. Ignoring case in the local part too is `luci-sso`'s policy, not a standard's rule; see [About Roles and Permissions](../explanation/roles-and-permissions.md#verified-email-addresses).
- **No match.** A user who matches no role is refused with `USER_NOT_AUTHORIZED`.
- **Several matches.** Rights are never merged. The login's log line names the role chosen and the other matches.
- **Invalid roles.** A role that has neither an `email` nor a `group` entry is ignored, and the log says `Ignoring role '<name>': missing email or group list`. If no valid role is left, the service reports `CONFIG_ERROR` (`No valid roles found in /etc/config/luci-sso`).
- **Leftover `read`/`write`.** Releases before role permissions moved to `rpcd` kept `read` and `write` lists on the role. They grant nothing now, and the log says `Ignoring read/write on role '<name>': its permissions are the rpcd login entry 'luci_sso_<name>'`. The package's install and upgrade script moves them into the entry.
- **Shipped role.** The package ships `config role 'admin'` with `list email 'admin@example.com'`. On install, if that role still matches only that address and has no entry, its entry gets `read '*'` and `write '*'`.

For worked examples, see [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md).

---

## Role Permissions (rpcd login entry)

Each role `<name>` has one login entry in `/etc/config/rpcd`:

```properties
config login 'luci_sso_<name>'
    option username 'sso:<name>'
    list read '<access group or pattern>'
    list write '<access group or pattern>'
```

| Option | Type | Description |
| :--- | :--- | :--- |
| section name | string | `luci_sso_<name>`. |
| section type | `login` | Required. |
| `username` | string | Required. `sso:<name>`. SSO sessions of the role carry this user name. |
| `read` | list (string) | Access groups the role may read. Always grants `unauthenticated` (see [notes](#role-permissions-notes)). |
| `write` | list (string) | Access groups the role may write; write implies read. |
| `password` | none | Never present. |

Access groups are the top-level keys of the JSON files in `/usr/share/rpcd/acl.d/`, such as `luci-mod-status-realtime`.

### Role permissions notes

- **Meaning.** The lists mean what they mean for an `rpcd` password login. Entries are `fnmatch(3)` patterns: `*` matches every access group. `!pattern` negates, and negations in a list are checked before its positive entries. A read that the `read` list neither allows nor denies falls back to the `write` list. Only `list` options count: `rpcd` ignores a single `option read`.
- **Rights.** A session gets exactly what `rpcd` grants a password login with the same lists: each permitted group's `read` or `write` section, expanded into its `ubus`, `uci`, `file` and `cgi-io` rights. `read '*'` with `write '*'` is what a stock `root` login gets.
- **Saving settings.** Saving anything in LuCI also needs `luci-base` in `write`, whose write section holds `uci set` and `uci apply`.
- **`unauthenticated`.** LuCI calls `session.access` and `luci.getFeatures`, which this group grants, on every page. A stored `read` list always grants it. A list that already grants it, by name or through a pattern such as `*`, is stored as given; any other list gets `unauthenticated` appended once. A list with a negation that denies it, such as `!unauthenticated` or `!*`, is refused.
- **Password.** An entry without a `password` option can rebuild sessions on an `rpcd` reload but can never be used to log in. An entry with one, even empty, makes the login fail with `INSECURE_RPCD_LOGIN`.
- **Missing entry.** A role without a usable entry (missing, not a `login`, or with another `username`) makes the login fail with `MISSING_RPCD_LOGIN`.
- **Reload.** `rpcd` rebuilds each session's rights from the entry named by the session's user name when it reloads, so SSO sessions keep their rights, and get the entry's new rights, across a reload.
- **Removal.** Removing the package copies each entry's lists back onto its role, as `list read` and `list write`, and deletes the entries. The next install moves them back. See [How to Remove luci-sso](../how-to/sysadmin/uninstall.md).

---

## The `luci-sso` ubus object

The `luci-sso` ubus object, an `rpcd` plugin at `/usr/share/rpcd/ucode/luci-sso.uc`, is the interface that writes the role entries. The settings page uses it; so can `ubus call` on the router. It touches only `luci_sso_*` sections, and stages its changes in a private UCI delta directory, so it never commits changes to `rpcd` that someone else staged.

| Method | Arguments | Reply |
| :--- | :--- | :--- |
| `list_roles` | none | `{ "roles": [ { "name", "read", "write" } ], "reload_pending": <bool> }`: every `luci_sso_*` login entry, in file order. |
| `set_role` | `name` (string), `read` (array), `write` (array) | `{ "role": { "name", "read", "write" } }`, with the lists as stored. Creates or replaces the entry, and removes any `password` option. |
| `delete_role` | `name` (string) | `{ "result": true }` |

| Rule | Limit |
| :--- | :--- |
| `name` | 1–32 characters: letters, digits and underscores. |
| `read`, `write` | Arrays of at most 128 strings. Both are required; an empty array is allowed. |
| Each list entry | 1–128 characters, no control characters. `rpcd` globs and `!` negations are allowed. |

Errors come back as a reply `{ "error": "<CODE>", "message": "<text>" }`. `rpcd` itself refuses an argument of the wrong type, or an unknown one, with `UBUS_STATUS_INVALID_ARGUMENT`.

| Error | Cause |
| :--- | :--- |
| `INVALID_NAME` | The name is missing, too long, or has other characters. |
| `INVALID_LIST` | A list is not an array of strings, is too long, has an empty, too long or control-character entry, or its `read` list denies `unauthenticated`. |
| `NOT_FOUND` | `delete_role`: the role has no entry. |
| `COMMIT_FAILED` | `/etc/config/rpcd` could not be written. |

After a successful write, the plugin makes `rpcd` reload one second after the reply, as `/etc/init.d/rpcd reload` does. Writes in that second share the reload. `list_roles` reports `"reload_pending": true` from the write until `rpcd` has restarted.

Access through LuCI needs the `luci-app-sso` access group: its `read` section grants `list_roles`, its `write` section `set_role` and `delete_role`. It grants no UCI access to `rpcd`.

---

## LuCI Form ↔ UCI Option

The settings page at **Services > Single Sign-On** (view `services/sso`, heading **SSO Login**) edits `/etc/config/luci-sso`, and the roles' `rpcd` login entries through the [`luci-sso` ubus object](#the-luci-sso-ubus-object). Opening it needs the `luci-app-sso` access group. **Save & Apply** writes the form with `uci`; **Reset** reloads the last saved values without writing.

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
| **Require Verified Email** | `require_email_verified` | Checkbox; saved as `1` or `0`. Ticked when the option is unset, and then saved as `1`. |
| **Clock Tolerance** | `clock_tolerance` | Required integer, `0`–`3600`. Form default: `60`. |
| **Internal Issuer URL** | `internal_issuer_url` | Optional; must start with `https://`. Placeholder: `https://<browser host>:8443`. The form does not check that the value is an origin with no path; a path is rejected at login with `CONFIG_ERROR`. |

### Users section

Each row is a `config role '<name>'` section and its `rpcd` login entry. The rows are in the order roles are tried; dragging a row reorders the sections. **Add** takes the role name, which becomes the section name; the name `default` is refused, because it belongs to the OIDC section. Each row's **Edit** button opens the role's editor; its **Delete** button deletes the section and the entry.

The table's **Emails** and **Groups** columns list the role's values, or `(none)`. **Read Access** and **Write Access** list the entry's lists, without `unauthenticated`:

| Cell | Meaning |
| :--- | :--- |
| `(none)` | The list is empty. |
| `(none): this role grants no access` | Both lists are empty apart from `unauthenticated`. The role's users can log in but see nothing. |
| `Not set: edit and save this role, or its users cannot log in` | The role has no entry. |
| `(unavailable)` | `list_roles` failed. The access fields are read-only, and nothing is written to `rpcd`. |

| Field (role editor) | Stored in | Form behaviour |
| :--- | :--- | :--- |
| **Email Addresses** | `email` | List; one address per entry. |
| **Groups** | `group` | List; one group per entry. |
| **Read Access** | `read` of `luci_sso_<name>` | List of access groups. `unauthenticated` is not shown, and is always stored. |
| **Write Access** | `write` of `luci_sso_<name>` | List of access groups. |

The editor says "Permission changes take effect when you click Save at the bottom of the page." Its own **Save** keeps the edit on the page only. The page's **Save** (and **Save & Apply**) stages the UCI changes, then sends each edited role to `set_role` and each deleted one to `delete_role`, and waits for `rpcd` to reload. A new role always gets an entry, even with both lists empty. An error from the object is shown and stops **Save & Apply**. Emails, groups and the order take effect with **Save & Apply**.

Matching rules are in [Role Mapping](#role-mapping-config-role); permission rules in [Role Permissions](#role-permissions-rpcd-login-entry).

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
    option require_email_verified '1'

config role 'admin'
    list email 'admin@example.com'
    list group 'admins'
```

The role's permissions, in `/etc/config/rpcd`:

```properties
config login 'luci_sso_admin'
    option username 'sso:admin'
    list read '*'
    list write '*'
```
