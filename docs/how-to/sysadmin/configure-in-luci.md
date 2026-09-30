# How to Configure luci-sso in the LuCI Web Interface

This guide enters or updates the identity provider's settings and the access roles on the **Services > Single Sign-On** page. Use it when you already have a client ID and secret from your identity provider.

If you are connecting to a provider for the first time, use the [provider guides](../index.md#identity-providers) instead: they cover the IdP registration and these router settings together. For what each field stores, see [LuCI Form ↔ UCI Option](../../reference/uci-config.md#luci-form-uci-option).

---

## 1. Open the settings page

Log in to LuCI and navigate to **Services > Single Sign-On**. The page heading reads **SSO Login**. It has two sections: **Settings** and **Users**.

![The SSO Login page filled in with example values. Settings: Enable SSO ticked, Issuer URL https://auth.example.com, Client ID luci-router, Client Secret masked as dots, Redirect URI starting https://router.example.com/cgi-bin/, Scopes openid profile email groups, Require Verified Email ticked with a note that a user is matched by email address only if the provider marks it as verified and that group matching is not affected, Clock Tolerance 60, and an empty Internal Issuer URL showing a placeholder. Users: a line saying a user gets the first role, from the top, whose emails or groups match, and that rows can be dragged to change the order; a line saying read and write access are written when you press Save or Save & Apply, while emails, groups and order take effect with Save & Apply; then a table with Name, Emails, Groups, Read Access and Write Access columns. The admin row has admin@example.com, (none) for groups, and * for read and write; the viewer row has bob@example.com, group network-viewers, read luci-base, luci-mod-status-* and luci-mod-network-*, and (none) for write. Each row has a drag handle and Edit and Delete buttons. Below are a name field with an Add button and the Save & Apply, Save and Reset buttons.](../../assets/screenshots/luci-sso-settings.png "Services > Single Sign-On: the Settings and Users sections")

---

## 2. Fill in the Settings section

1.  Enter the **Issuer URL**, **Client ID** and **Client Secret** from your identity provider. The Issuer URL must be exactly the `issuer` your provider declares.
2.  Check the **Redirect URI**. If none is saved yet, the field suggests `https://<host>/cgi-bin/luci-sso/callback` with the host name you opened LuCI at, without its port. Keep it only if users will open LuCI at that same host name; otherwise, replace the host. Behind a reverse proxy, use the proxy's public host name; see [How to Run LuCI Behind a Reverse Proxy](reverse-proxy.md#3-use-the-public-host-name-in-the-sso-settings). The value must match the redirect URI registered with the IdP exactly.
3.  If you map users by group, add `groups` to **Scopes** (for example `openid profile email groups`), provided your IdP supports it. See [How to Configure Role-Based Access Control](rbac.md).
4.  Leave **Require Verified Email** ticked. Clear it only if your IdP cannot send `email_verified: true` and users cannot set their own address; see [About Roles and Permissions](../../explanation/roles-and-permissions.md#verified-email-addresses).
5.  If the router reaches the IdP at a different address than browsers do, set **Internal Issuer URL** to that origin (`https://host[:port]`, no path). Otherwise leave it empty. See [How to Configure Split-Horizon Networking](split-horizon.md).
6.  Leave **Clock Tolerance** at `60` unless logins fail with `TOKEN_EXPIRED` or `TOKEN_ISSUED_IN_FUTURE` while the clocks look right.
7.  Tick **Enable SSO** only when the connection test passes and at least one role is ready.

---

## 3. Test the connection

Before you enable SSO, click **Test connection**, below **Internal Issuer URL**. The router checks the values in the form, including changes you have not saved, against the identity provider. It saves nothing, and it works while SSO is disabled. The test takes a few seconds; each request to the provider gives up after 5 seconds.

The page lists one line per check, each marked **Pass**, **Fail**, **Warning** (the router could not tell) or **Skipped** (an earlier check failed):

| Check | What it verifies | If it fails |
| :--- | :--- | :--- |
| **Issuer URL** | The Issuer URL is set and starts with `https://`. | Enter the provider's issuer. |
| **Discovery** | The router can fetch `<issuer>/.well-known/openid-configuration`, from the Internal Issuer URL's origin when that is set. | The line names the cause: no answer in time, a certificate the router does not trust, a refused connection, or the provider's HTTP status. See [A back-channel request to the IdP failed](debugging.md#a-back-channel-request-to-the-idp-failed). |
| **Issuer** | The document's `issuer` is exactly the Issuer URL. | Set **Issuer URL** to the value the line quotes. When the two differ only in a trailing slash, letter case or default port, the line says so. |
| **Endpoints** | The document has an authorization, token and JWK Set endpoint, all HTTPS. | The provider is misconfigured, or the Issuer URL points at the wrong service. |
| **Signing keys** | The JWK Set loads and holds at least one key `luci-sso` can verify ID tokens with: RS256 (RSA), or ES256 (EC P-256). | Configure an RS256 or ES256 signing key at the provider. |
| **Redirect URI** | The Redirect URI is set, uses HTTPS, and ends in `/cgi-bin/luci-sso/callback`. | Correct it, and register the same address with the provider. |
| **Client credentials** | The provider accepts the Client ID and Client Secret. | **Fail** (`invalid_client`, or HTTP 401): copy both again from the provider. **Warning**: the provider's answer did not say; the line quotes it. |

The client credentials check is a standard, harmless probe. The router sends the provider's token endpoint a token request, authenticated exactly as at login (`client_secret_post`: the ID and secret in the form body), with an authorization code it made up and a new PKCE verifier. A provider checks the client before the code, so it answers `invalid_grant` when the credentials are right, and `invalid_client` when they are wrong. The made-up code cannot be redeemed, no token is issued, and the provider's log may show one refused token request. The secret is never shown on the page or written to the log, and the test writes nothing on the router: not the settings, and not the discovery or key caches a login uses.

The test does not check the roles, and it cannot tell whether the Redirect URI is registered at the provider: only a real login shows that.

---

## 4. Add or change roles in the Users section

A role says who may log in (by email, group or subject) and which LuCI access groups they get. Roles are tried from the top of the table, and a user gets the **first** role that matches. Rights from several roles are never merged.

To add a role:

1.  Type a name (letters, digits and underscores, at most 32; not `default`) and click **Add**.
2.  In the role editor, add entries to **Email Addresses**, **Groups**, or both. A role with neither is ignored.
3.  Add access groups to **Read Access** and **Write Access**. For a full administrator, put `*` in both. For a role that may save settings, include `luci-base` in **Write Access**. Leave `unauthenticated` out: it is always included.
4.  Click **Save** to close the editor. As the note in the editor says, the permissions are written only when you click **Save** at the bottom of the page.

![The role editor for a role named viewer, titled "User Role: viewer". Email Addresses holds bob@example.com and Groups holds network-viewers. Below them, the note "Permission changes take effect when you click Save at the bottom of the page." Read Access holds luci-base, luci-mod-status-* and luci-mod-network-*, and Write Access is empty. Each list has an empty field with a + button for another entry, and the editor has Dismiss and Save buttons.](../../assets/screenshots/luci-sso-role-editor.png "The role editor, opened with Edit on the viewer row")

To change a role, click **Edit** in its row. To remove one, click **Delete**; a user who matched only that role gets `USER_NOT_AUTHORIZED` at their next login.

To change the order, drag a row by its handle. Put the most privileged or most specific role at the top.

Check the **Read Access** column for warnings:

- `(none): this role grants no access`: the role's users can log in but see nothing.
- `Not set: edit and save this role, or its users cannot log in`: the role has no permissions in `rpcd`. Click **Edit**, then **Save**, and save the page.

For which access groups to grant, see [How to Configure Role-Based Access Control](rbac.md).

---

## 5. Save and apply

Click **Save & Apply**.

- **Read Access** and **Write Access** go to `rpcd` as soon as the page is saved. The page shows "Saving role permissions; rpcd is reloading to apply them…", then "Role permissions saved and in force." Users already logged in with that role get the new rights at once.
- Everything else, including emails, groups and the order of the roles, applies from the next login. There is no service to restart: `luci-sso` reads the configuration on every request.

If `rpcd` refuses a role's permissions, the page shows the error and does not apply the rest. Fix the role and save again.

To discard unsaved edits, click **Reset**.

---

## 6. Check the result

On the router:

```bash
uci get luci-sso.default.redirect_uri
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
```

The first command prints the saved redirect URI; confirm it matches the value registered with your IdP. The second answers `{"enabled": true}` once SSO is enabled and the configuration is complete (with a missing or invalid option it returns an error page instead); then log out and use the SSO button on the login page. If the login fails, see [How to Debug luci-sso](debugging.md).

---

## Next steps

- Map users by group instead of email: [How to Configure Role-Based Access Control](rbac.md)
- Update credentials after a provider rotation: [How to Rotate Credentials](rotate-credentials.md)
- Configure a split-horizon setup: [How to Configure Split-Horizon Networking](split-horizon.md)
- Serve LuCI through a reverse proxy that terminates TLS: [How to Run LuCI Behind a Reverse Proxy](reverse-proxy.md)
