# How to Configure Pocket ID

This guide describes how to connect `luci-sso` to a [Pocket ID](https://pocket-id.org/) instance.

Pocket ID is a self-hosted OIDC provider built around passkeys — users authenticate with biometrics or hardware security keys instead of passwords. Users must have a passkey enrolled in Pocket ID before they can complete an SSO login on your router.

---

## 1. Create an OIDC client in Pocket ID

Log in to your Pocket ID admin interface and navigate to **OIDC Clients > Create**.

Fill in the following:

| Field | Value |
| :--- | :--- |
| **Name** | `luci-router` (or any label you prefer) |
| **Callback URL** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |

Save the client. Pocket ID will display the generated **Client ID** and **Client Secret** — copy both.

If you want to restrict which Pocket ID groups are allowed to authenticate to this client, enable **Allowed User Groups** and select the relevant groups before saving.

---

## 2. Configure the router

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://id.example.com` |
    | **Client ID** | Your Client ID from Step 1 |
    | **Client Secret** | Your Client Secret from Step 1 |
    | **Redirect URI** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |

    Replace `https://id.example.com` with the actual URL of your Pocket ID instance. The Redirect URI must exactly match the callback URL set in Step 1; the shipped configuration has `https://router.lan/cgi-bin/luci-sso/callback` there.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://id.example.com'
    uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
    uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'
    uci set luci-sso.default.enabled='1'
    uci commit luci-sso
    ```

    Replace `https://id.example.com` with the actual URL of your Pocket ID instance. The `redirect_uri` must exactly match the callback URL set in Step 1.

---

## 3. Configure role mapping

### Map by email

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On** and scroll to the **Users** section.

    Click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the email address in **Email Addresses**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.email='user@example.com'
    uci commit luci-sso
    ```

### Map by group

Pocket ID exposes groups via the `groups` scope. Group names appear in the `groups` claim as `GroupName@PocketID` — include the suffix when configuring the role.

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**.

    In **Settings**, update **Scopes** to `openid profile email groups` and click **Save & Apply**.

    Scroll to **Users**, click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the group name (e.g. `router-admins@PocketID`) in **Groups**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.scope='openid profile email groups'
    uci commit luci-sso
    ```

    Then map the group to a LuCI role:

    ```bash
    uci add_list luci-sso.admin.group='router-admins@PocketID'
    uci commit luci-sso
    ```

---

## 4. Verify

Check that the service is active. On the router:

```bash
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
# Expected: {"enabled": true}
```

Open the LuCI login page at the host name used in the Redirect URI; the login fails with `MISSING_HANDSHAKE_COOKIE` if it starts at a different address. The **Login with SSO** button should appear. Clicking it redirects to your Pocket ID passkey authentication screen.

---

## Troubleshooting

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso
    ```

| Symptom | Likely cause |
| :--- | :--- |
| `[500] OIDC_DISCOVERY_FAILED`, preceded by `Discovery issuer mismatch: Requested [id: …], got [id: …]` | `issuer_url` must be the base URL of your Pocket ID instance (`https://id.example.com`), with no path. It must use the host name Pocket ID is configured with, not an IP address or another alias. |
| `USER_NOT_AUTHORIZED` | Authentication succeeded but no UCI role matched. If using group mapping, verify the group name includes the `@PocketID` suffix. |
| User is redirected back to the login page without an error | The user has no passkey registered in Pocket ID, or the Pocket ID client's **Allowed User Groups** excludes them. |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
