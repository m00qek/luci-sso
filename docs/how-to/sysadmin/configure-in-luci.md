# How to Configure luci-sso in the LuCI Web Interface

This guide enters or updates the identity provider's settings and the access roles on the **Services > Single Sign-On** page. Use it when you already have a client ID and secret from your identity provider.

If you are connecting to a provider for the first time, use the [provider guides](../index.md#identity-providers) instead: they cover the IdP registration and these router settings together. For what each field stores, see [LuCI Form ↔ UCI Option](../../reference/uci-config.md#luci-form-uci-option).

---

## 1. Open the settings page

Log in to LuCI and navigate to **Services > Single Sign-On**. The page heading reads **Single Sign-On**. It has two sections: **Identity provider**, with a **Provider** and an **Advanced** tab, and **Roles**.

![The Single Sign-On page filled in with example values. The Identity provider section shows its Provider tab, next to an Advanced tab: Issuer URL https://auth.example.com, described as your identity provider's address, exactly as it identifies itself; Client ID luci-router; Client Secret masked as dots; Redirect URI https://router.example.com/cgi-bin/luci-sso/callback in full, with a Copy button and the note to register this exact address with your identity provider; Scopes openid profile email groups; a Test connection button with a note that it checks the values in the form, including unsaved changes, and saves nothing; and Enable SSO ticked, last. The Roles section says who can log in and what they can do, that a user gets the first role from the top that matches, that rows can be dragged to reorder, and that changes take effect with Save & Apply. Its table has Name, Emails, Groups, Subjects, Read access and Write access columns. The admin row has admin@example.com, a dash for groups and subjects, Everything for read access and Full admin for write access; the viewer row has bob@example.com, group network-viewers, a dash for subjects, read access luci-base, luci-mod-status-* and luci-mod-network-*, and a dash for write access. Each row has a drag handle and Edit and Delete buttons. Below are a box with the placeholder New role name, e.g. viewers, an Add button, and the Save & Apply, Save and Reset buttons.](../../assets/screenshots/luci-sso-settings.png "Services > Single Sign-On: the Identity provider and Roles sections")

The page has one rule: changes take effect with **Save & Apply**. **Save** keeps your changes, including role permissions, on the page and in LuCI's list of unsaved changes, without applying them.

---

## 2. Fill in the Provider tab

The **Provider** tab lists the fields in the order you set them up: connect, test, switch on.

1.  Enter the **Issuer URL**, **Client ID** and **Client Secret** from your identity provider. The Issuer URL must be exactly the `issuer` your provider declares.
2.  Check the **Redirect URI**. If none is saved yet, the field suggests `https://<host>/cgi-bin/luci-sso/callback` with the host name you opened LuCI at, without its port. Keep it only if users will open LuCI at that same host name; otherwise, replace the host. Behind a reverse proxy, use the proxy's public host name; see [How to Run LuCI Behind a Reverse Proxy](reverse-proxy.md#3-use-the-public-host-name-in-the-sso-settings). Register this exact address with your identity provider: **Copy** next to the field copies it.
3.  If you map users by group, add `groups` to **Scopes** (for example `openid profile email groups`), provided your IdP supports it. See [How to Configure Role-Based Access Control](rbac.md). While a role matches by group and **Scopes** lacks `groups`, a warning under **Scopes** says so.
4.  Leave **Enable SSO**, the last field, for after the connection test.

---

## 3. Test the connection

Before you enable SSO, click **Test connection**, above **Enable SSO** on the **Provider** tab. The router checks the values in the form, including changes you have not saved, against the identity provider. It saves nothing, and it works while SSO is disabled. The test takes a few seconds; each request to the provider gives up after 5 seconds.

The page lists one line per check, each marked **Pass**, **Fail**, **Warning** (the router could not tell) or **Skipped** (an earlier check failed):

| Check | What it verifies | If it fails |
| :--- | :--- | :--- |
| **Issuer URL** | The Issuer URL is set and starts with `https://`. | Enter the provider's issuer. |
| **Discovery** | The router can fetch `<issuer>/.well-known/openid-configuration`, from the Internal Issuer URL's origin when that is set. | The line names the cause: no answer in time, a certificate the router does not trust, a refused connection, or the provider's HTTP status. See [A back-channel request to the IdP failed](debugging.md#a-back-channel-request-to-the-idp-failed). |
| **Issuer** | The document's `issuer` is exactly the Issuer URL. | Set **Issuer URL** to the value the line quotes. When the two differ only in a trailing slash, letter case or default port, the line says so. |
| **Endpoints** | The document has an authorization, token and JWK Set endpoint, all HTTPS. | The provider is misconfigured, or the Issuer URL points at the wrong service. |
| **Signing keys** | The JWK Set loads and holds at least one key `luci-sso` can verify ID tokens with: RS256 (RSA, at least 2048 bits, exponent 65537), or ES256 (EC P-256). | Configure such a signing key at the provider. When the line says the RSA key is too short, create a 2048-bit or longer key at the provider and sign with it. |
| **Redirect URI** | The Redirect URI is set, uses HTTPS, and ends in `/cgi-bin/luci-sso/callback`. | Correct it, and register the same address with the provider. |
| **Client credentials** | The provider accepts the Client ID and Client Secret. | **Fail** (`invalid_client`, or HTTP 401): copy both again from the provider. **Warning**: the provider's answer did not say; the line quotes it. |

The client credentials check is a standard, harmless probe. The router sends the provider's token endpoint a token request, authenticated exactly as at login (`client_secret_post`: the ID and secret in the form body), with an authorization code it made up and a new PKCE verifier. A provider checks the client before the code, so it answers `invalid_grant` when the credentials are right, and `invalid_client` when they are wrong. The made-up code cannot be redeemed, no token is issued, and the provider's log may show one refused token request. The secret is never shown on the page or written to the log, and the test writes nothing on the router: not the settings, and not the discovery or key caches a login uses.

The test does not check the roles, and it cannot tell whether the Redirect URI is registered at the provider: only a real login shows that.

When every check passes and at least one role is ready, tick **Enable SSO**.

---

## 4. Check the Advanced tab

The defaults suit most setups.

1.  Leave **Require Verified Email** ticked. Clear it only if your IdP cannot send `email_verified: true` and users cannot set their own address; see [About Roles and Permissions](../../explanation/roles-and-permissions.md#verified-email-addresses). While it is ticked, a warning under it names the roles that match by email only: they let a user in only if the IdP marks the address as verified.
2.  Leave **Clock Tolerance** at `60` unless logins fail with `TOKEN_EXPIRED` or `TOKEN_ISSUED_IN_FUTURE` while the clocks look right.
3.  If the router reaches the IdP at a different address than browsers do, set **Internal Issuer URL** to that origin (`https://host[:port]`, no path). Otherwise leave it empty. See [How to Configure Split-Horizon Networking](split-horizon.md).
4.  Leave **Trusted Proxy** empty unless LuCI sits behind a reverse proxy that limits each client itself. See [How to Run LuCI Behind a Reverse Proxy](reverse-proxy.md#4-exempt-the-proxy-from-luci-ssos-per-client-limits).

---

## 5. Add or change roles in the Roles section

A role says who may log in (by email, group or subject) and which LuCI access groups they get. Roles are tried from the top of the table, and a user gets the **first** role that matches. Rights from several roles are never merged.

To add a role:

1.  Type a name in the box next to **Add**, and click **Add**. A name has letters, digits and underscores only, at most 32 of them, and cannot be `default` or an existing role's; the box says what is wrong while you type, and **Add** stays disabled until the name is valid.
2.  In the role editor, add entries to **Emails**, **Groups** or **Subjects**. A role with none is ignored.
3.  Add access groups to **Read access** and **Write access**. Each list offers the access groups installed on the router, and takes any name or pattern you type, such as `luci-mod-status-*`. For a full administrator, pick `*` in both. For a role that may save settings, include `luci-base` in **Write access**. Leave `unauthenticated` out: it is always included.
4.  Click **Save** to close the editor. As the note in the editor says, your changes stay on the page until you click **Save & Apply**.

![The role editor for a role named viewer, titled "Role: viewer". Emails holds bob@example.com, Groups holds network-viewers, and Subjects is empty, each with a short explanation; the Subjects note says the sub claim is compared exactly and links to matching by subject. Below them, the note "Changes here are kept on the page until you Save & Apply it." Read access holds luci-base, luci-mod-status-* and luci-mod-network-*, with a drop-down to choose or type another group; Write access is empty, with the same drop-down. The editor has Dismiss and Save buttons.](../../assets/screenshots/luci-sso-role-editor.png "The role editor, opened with Edit on the viewer row")

To change a role, click **Edit** in its row. To remove one, click **Delete**; a user who matched only that role gets `USER_NOT_AUTHORIZED` at their next login.

To change the order, drag a row by its handle. Put the most privileged or most specific role at the top.

The table shows `*` in **Read access** as **Everything**, `*` in **Write access** as **Full admin**, and an empty list as a dash. Check the **Read access** column for warnings:

- `None: this role grants no access`: the role's users can log in but see nothing.
- `Not set: edit this role and Save & Apply, or its users cannot log in`: the role has no permissions in `rpcd`. Click **Edit**, then **Save** in the editor, then **Save & Apply**.

For which access groups to grant, see [How to Configure Role-Based Access Control](rbac.md).

---

## 6. Save and apply

Click **Save & Apply**.

1.  LuCI applies the settings, the matching rules and the order of the roles, as for any page, and confirms that the router is still reachable.
2.  Only once LuCI has confirmed the apply, the page writes **Read access** and **Write access** to `rpcd`. It shows "Saving role permissions; rpcd is reloading to apply them…", then "Role permissions saved and in force.", and reloads. Users already logged in with that role get the new rights at once.

If the apply is rolled back, no permissions are written: your permission changes stay on the page, to apply again. If `rpcd` refuses a role's permissions, the page shows the error, with the settings already applied; fix the role and click **Save & Apply** again.

Everything but permissions applies from the next login. There is no service to restart: `luci-sso` reads the configuration on every request.

**Save** alone applies nothing. It keeps the settings and roles in LuCI's unsaved changes and the permission changes on the page, until **Save & Apply**. Permission changes live only in the open page: reload or leave it, and they are gone, while the other unsaved changes stay. To discard unsaved changes, click **Reset**.

---

## 7. Check the result

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
