# How to Configure luci-sso in the LuCI Web Interface

This guide enters or updates the identity provider's settings and the access roles on the **Services > Single Sign-On** page. Use it when you already have a client ID and secret from your identity provider.

If you are connecting to a provider for the first time, use the [provider guides](../index.md#identity-providers) instead: they cover the IdP registration and these router settings together. For what each field stores, see [LuCI Form ↔ UCI Option](../../reference/uci-config.md#luci-form-uci-option).

---

## 1. Open the settings page

Log in to LuCI and navigate to **Services > Single Sign-On**. The page heading reads **SSO Login**. It has two sections: **Settings** and **Users**.

![The SSO Login page filled in with example values. Settings: Enable SSO ticked, Issuer URL https://auth.example.com, Client ID luci-router, Client Secret masked as dots, Redirect URI starting https://router.example.com/cgi-bin/, Scopes openid profile email groups, Clock Tolerance 60, and an empty Internal Issuer URL showing a placeholder. Users: a line saying a user gets the first role, from the top, whose emails or groups match, and that rows can be dragged to change the order; a line saying read and write access are written when you press Save or Save & Apply, while emails, groups and order take effect with Save & Apply; then a table with Emails, Groups, Read Access and Write Access columns. The admin row has admin@example.com and * for read and write; the viewer row has bob@example.com, group network-viewers, read luci-base, luci-mod-status-* and luci-mod-network-*, and no write. Each row has a drag handle and Edit and Delete buttons. Below are a name field with an Add button and the Save & Apply, Save and Reset buttons.](../../assets/screenshots/luci-sso-settings.png "Services > Single Sign-On: the Settings and Users sections")

---

## 2. Fill in the Settings section

1.  Enter the **Issuer URL**, **Client ID** and **Client Secret** from your identity provider. The Issuer URL must be exactly the `issuer` your provider declares.
2.  Check the **Redirect URI**. If none is saved yet, the field suggests `https://<host>/cgi-bin/luci-sso/callback` with the host name you opened LuCI at, without its port. Keep it only if users will open LuCI at that same host name; otherwise, replace the host. The value must match the redirect URI registered with the IdP exactly.
3.  If you map users by group, add `groups` to **Scopes** (for example `openid profile email groups`), provided your IdP supports it. See [How to Configure Role-Based Access Control](rbac.md).
4.  If the router reaches the IdP at a different address than browsers do, set **Internal Issuer URL** to that origin (`https://host[:port]`, no path). Otherwise leave it empty. See [How to Configure Split-Horizon Networking](split-horizon.md).
5.  Leave **Clock Tolerance** at `60` unless logins fail with `TOKEN_EXPIRED` or `TOKEN_ISSUED_IN_FUTURE` while the clocks look right.
6.  Tick **Enable SSO** when the settings and at least one role are ready.

---

## 3. Add or change roles in the Users section

A role says who may log in (by email or group) and which LuCI access groups they get. Roles are tried from the top of the table, and a user gets the **first** role that matches. Rights from several roles are never merged.

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

## 4. Save and apply

Click **Save & Apply**.

- **Read Access** and **Write Access** go to `rpcd` as soon as the page is saved. The page shows "Saving role permissions; rpcd is reloading to apply them…", then "Role permissions saved and in force." Users already logged in with that role get the new rights at once.
- Everything else, including emails, groups and the order of the roles, applies from the next login. There is no service to restart: `luci-sso` reads the configuration on every request.

If `rpcd` refuses a role's permissions, the page shows the error and does not apply the rest. Fix the role and save again.

To discard unsaved edits, click **Reset**.

---

## 5. Check the result

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
