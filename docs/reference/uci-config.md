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

- **`issuer_url`** must be identical to the `issuer` value the IdP declares in its discovery document (OIDC Discovery §4.3). The comparison is exact: a trailing slash, letter case and an explicit `:443` all count. [Provider Compatibility](provider-compatibility.md#issuer-identifiers) lists each provider's format.
- **`internal_issuer_url`** applies to the router's back-channel HTTP requests: discovery, token exchange, JWKS fetch and UserInfo.
    - Back-channel URLs on `issuer_url`'s origin get this origin instead. Their paths are kept. With `issuer_url` `https://kc.example.com/realms/home` and `internal_issuer_url` `https://10.0.0.5:8443`, discovery is fetched from `https://10.0.0.5:8443/realms/home/.well-known/openid-configuration`.
    - A value that does not use `https://`, or has a path, query or fragment, is rejected with `CONFIG_ERROR`.
    - The `iss` claim is still validated against `issuer_url`.
    - See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md).
- **`require_email_verified`** affects role matching only.
    - The claim is read from the response the email came from: the ID Token, or UserInfo when the ID Token has no `email`. The two are never mixed.
    - Only the JSON boolean `true` counts, as OIDC Core §5.1 defines the claim. Any other value, including the string `"true"`, or no claim, is not verified.
    - An unverified email is ignored for matching, and the log says `Ignoring the unverified email of user [sub_id: …] for role matching: email_verified is not true (require_email_verified)`. `group` rules still match. A user who matches no role is refused with `USER_NOT_AUTHORIZED`.
    - The session's `oidc_user` label holds only a verified email, whether the option is on or off. An unverified email is not stored.
    - What each IdP sends: [Provider Compatibility](provider-compatibility.md#verified-email). Why: [About Roles and Permissions](../explanation/roles-and-permissions.md#verified-email-addresses).
- **`clock_tolerance`** has no built-in code default: if it is absent, the service reports `CONFIG_ERROR`. The shipped UCI configuration sets it to `60`.

---

## Role Mapping (`config role`)

Each `config role '<name>'` section says which users get the role. What the role grants is its `rpcd` login entry, described in [Role Permissions (rpcd login entry)](#role-permissions-rpcd-login-entry). `rpcd` is the OpenWrt daemon that holds LuCI sessions and their rights.

A role matches a user if ANY of its `email`, `group` or `sub` values matches. Roles are tried in the order of their sections in `/etc/config/luci-sso`; the user gets the **first** role that matches, and only that one.

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC `email` claim, ignoring letter case in the whole address. Only a verified email matches while `require_email_verified` is on (the default). See [notes](#role-mapping-notes). |
| `group` | list (string) | Match by a value of the OIDC `groups` claim, which must be a JSON array. Case-sensitive. |
| `sub` | list (string) | Match by the OIDC `sub` claim of the ID Token: exact, case-sensitive string equality. The issuer is implied: it is always `issuer_url`. See [notes](#role-mapping-notes). |

### Role mapping notes

- **Section name.** The role's name. `default` is taken by the OIDC section. The role's `rpcd` entry needs a name of 1–32 letters, digits and underscores; a role with a longer name can exist in UCI, but it cannot get permissions, and its users cannot log in.
- **Email case.** `Alice@Example.com` and `alice@example.com` match the same rule. Ignoring case in the local part too is `luci-sso`'s policy, not a standard's rule; see [About Roles and Permissions](../explanation/roles-and-permissions.md#verified-email-addresses).
- **Subject.** A `sub` value matches only the identical string: no letter-case folding, trimming, prefix or pattern. A `sub` claim that is missing, empty or not a string matches no rule. `require_email_verified` does not affect it. Why: [Matching by subject](../explanation/roles-and-permissions.md#matching-by-subject).
- **No match.** A user who matches no role is refused with `USER_NOT_AUTHORIZED`. The error page shows that user their own `sub`, HTML-escaped, and asks them to give it to the administrator. The log records only its hash (`sub_id`).
- **Several matches.** Rights are never merged. The login's log line names the role chosen and the other matches.
- **Invalid roles.** A role that has no `email`, `group` or `sub` entry is ignored, and the log says `Ignoring role '<name>': missing email, group or sub list`. If no valid role is left, the service reports `CONFIG_ERROR` (`No valid roles found in /etc/config/luci-sso`).
- **Leftover `read`/`write`.** Releases before role permissions moved to `rpcd` kept `read` and `write` lists on the role. They grant nothing now, and the log says `Ignoring read/write on role '<name>': its permissions are the rpcd login entry 'luci_sso_<name>'`. The package's install and upgrade script moves them into the entry.
- **Shipped role.** The package ships `config role 'admin'` with `list email 'admin@example.com'`. On install, if that role still matches only that address (no other email, no group, no sub) and has no entry, its entry gets `read '*'` and `write '*'`.

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

The `luci-sso` ubus object, an `rpcd` plugin at `/usr/share/rpcd/ucode/luci-sso.uc`, is the interface that writes the role entries, and runs the settings page's connection test. The settings page uses it; so can `ubus call` on the router. It touches only `luci_sso_*` sections, and stages its changes in a private UCI delta directory, so it never commits changes to `rpcd` that someone else staged.

| Method | Arguments | Reply |
| :--- | :--- | :--- |
| `list_roles` | none | `{ "roles": [ { "name", "read", "write" } ], "reload_pending": <bool> }`: every `luci_sso_*` login entry with a valid role name, in file order. |
| `set_role` | `name` (string), `read` (array), `write` (array) | `{ "role": { "name", "read", "write" } }`, with the lists as stored. Creates or replaces the entry, and removes any `password` option. |
| `delete_role` | `name` (string) | `{ "result": true }` |
| `test_connection` | `issuer_url`, `internal_issuer_url`, `client_id`, `client_secret`, `redirect_uri` (strings; missing counts as empty) | `{ "job": "<id>" }`. Starts a [connection test](#connection-test) in the background and answers at once. |
| `test_connection_result` | `job` (string) | `{ "done": false }` while the test runs; then `{ "done": true, "checks": [ { "id", "status", "message" } ] }`, or `{ "done": true, "error", "message" }` when the test itself failed. |

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
| `NOT_FOUND` | `delete_role`: the role has no entry. `test_connection_result`: no test with that `job`; only the latest test is kept, in memory, and an `rpcd` restart drops it. |
| `COMMIT_FAILED` | `/etc/config/rpcd` could not be written. |
| `BUSY` | `test_connection`: a test is already running. One runs at a time. |
| `TIMEOUT` | `test_connection_result`: the test did not finish within 25 seconds and was stopped. |
| `TEST_FAILED` | `test_connection` could not start the test, or it stopped without a result. |

After a successful write, the plugin makes `rpcd` reload one second after the reply, as `/etc/init.d/rpcd reload` does. Writes in that second share the reload. `list_roles` reports `"reload_pending": true` from the write until `rpcd` has restarted. While `rpcd` restarts, a `/ubus/` request that reaches it at the moment it re-executes itself is never answered: `uhttpd` waits for its session check up to half its script timeout (30 s by default) and serves no page meanwhile. Every `rpcd` reload can do this, whatever triggers it. The settings page waits up to 45 seconds for the reload.

Access through LuCI needs the `luci-app-sso` access group: its `read` section grants `list_roles`, its `write` section `set_role`, `delete_role`, `test_connection` and `test_connection_result`. A user who may only read the settings page cannot run the connection test, since it sends the client secret to the provider. The group grants no UCI access to `rpcd`.

### Connection test

`test_connection` runs these checks in order, through the same discovery, JWK Set and token-request code as a login, and returns one entry for each, always in this order. `status` is `pass`, `fail`, `warn` (could not tell) or `skip` (a check it depends on failed); `message` is an English sentence for the administrator.

| `id` | Passes when |
| :--- | :--- |
| `issuer_https` | `issuer_url` is set and starts with `https://`. |
| `discovery` | The discovery document is fetched with status 200 and is a JSON object. With `internal_issuer_url`, from its origin plus the issuer's path, as at login. `internal_issuer_url` must be an HTTPS origin with no path. |
| `issuer_match` | The document's `issuer` is exactly `issuer_url`. A failure's message says when the two differ only in a trailing slash, letter case or default port. |
| `endpoints` | `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present and HTTPS. |
| `jwks` | The JWK Set has at least one key with no `use` or `use` `sig`, no `alg` or an `alg` of `RS256` (RSA) or `ES256` (EC), and a public key the router can build: RSA, or EC on P-256. |
| `redirect_uri` | `redirect_uri` is set, starts with `https://`, and ends in `/cgi-bin/luci-sso/callback`. |
| `client_credentials` | A token request with a made-up authorization code, `client_id` and `client_secret` in the form body (`client_secret_post`, as at login) and a new PKCE verifier gets `invalid_grant`. `invalid_client`, or HTTP 401, fails; any other answer is `warn`, and the message quotes the OAuth `error` or the HTTP status. |

With `internal_issuer_url`, the JWK Set and token requests go to the internal origin too, as at login. Each HTTP request gives up after 5 seconds, and the test after 25. It runs in a child process of `rpcd`, so `rpcd` keeps answering meanwhile. It reads no cache and writes nothing on the router; its log lines start with `Connection test:`. `client_secret` is never part of a reply or a log line.

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
| **Test Connection** | none | A **Test connection** button. Sends the form's Issuer URL, Internal Issuer URL, Client ID, Client Secret and Redirect URI, saved or not, to [`test_connection`](#connection-test), and lists each check's result as `[Pass]`, `[Fail]`, `[Warning]` or `[Skipped]`, with a summary line. Saves nothing; works while **Enable SSO** is off. Needs write access to the `luci-app-sso` group. |

### Users section

Each row is a `config role '<name>'` section and its `rpcd` login entry. The rows are in the order roles are tried; dragging a row reorders the sections. **Add** takes the role name, which becomes the section name; the name `default` is refused, because it belongs to the OIDC section. Each row's **Edit** button opens the role's editor; its **Delete** button deletes the section and the entry.

The table's **Emails**, **Groups** and **Subjects** columns list the role's values, or `(none)`. **Read Access** and **Write Access** list the entry's lists, without `unauthenticated`:

| Cell | Meaning |
| :--- | :--- |
| `(none)` | The list is empty. |
| `(none): this role grants no access` | Both lists are empty apart from `unauthenticated`. The role's users can log in but see nothing. Shown in both cells. |
| `Not set: edit and save this role, or its users cannot log in` | The role has no entry. Shown in both cells. |
| `(unavailable)` | `list_roles` failed. The access fields are read-only, and nothing is written to `rpcd`. |

| Field (role editor) | Stored in | Form behaviour |
| :--- | :--- | :--- |
| **Email Addresses** | `email` | List; one address per entry. |
| **Groups** | `group` | List; one group per entry. |
| **Subjects (sub)** | `sub` | List; one `sub` value per entry, compared exactly. |
| **Read Access** | `read` of `luci_sso_<name>` | List of access groups. `unauthenticated` is not shown, and is always stored. |
| **Write Access** | `write` of `luci_sso_<name>` | List of access groups. |

The editor says "Permission changes take effect when you click Save at the bottom of the page." Its own **Save** keeps the edit on the page only. The page's **Save** (and **Save & Apply**) stages the UCI changes, then sends each edited role to `set_role` and each deleted one to `delete_role`, and waits for `rpcd` to reload. A new role always gets an entry, even with both lists empty. An error from the object is shown and stops **Save & Apply**. Emails, groups, subjects and the order take effect with **Save & Apply**.

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
