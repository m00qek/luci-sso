# How-to: Configure Google OIDC

This guide describes how to connect `luci-sso` to Google Workspace or a personal Google Cloud project.

---

## 1. Register an OAuth client in Google Cloud

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and sign in.
2. Create a new project (or select an existing one).
3. Navigate to **APIs & Services > OAuth consent screen**. Choose **Internal** (Google Workspace only) or **External** (personal accounts). Fill in an app name and contact email, then click through to **Save and Continue**.
4. Navigate to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
   - **Application type:** Web application.
   - **Name:** `LuCI Router`.
   - **Authorized redirect URIs:** `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback`.
5. Click **Create**. Copy the generated **Client ID** and **Client Secret**.

!!! note "External apps and test users"
    If you chose **External** on the OAuth consent screen, Google restricts sign-in to accounts listed as test users until the app is verified. Add your Gmail address under **OAuth consent screen > Test users** before proceeding.

---

## 2. Configure the router

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://accounts.google.com` |
    | **Client ID** | Your Client ID from Step 1 |
    | **Client Secret** | Your Client Secret from Step 1 |
    | **Redirect URI** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |
    | **Scopes** | `openid profile email` |
    | **Clock Tolerance** | `60` |

    The Redirect URI must exactly match the authorized redirect URI registered in Step 1.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://accounts.google.com'
    uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
    uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'
    uci set luci-sso.default.scope='openid profile email'
    uci set luci-sso.default.clock_tolerance='60'
    uci set luci-sso.default.enabled='1'
    uci commit luci-sso
    ```

    The `redirect_uri` must exactly match the authorized redirect URI registered in Step 1.

---

## 3. Configure role mapping

Google does not provide a `groups` claim for personal accounts. Map access by email address:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login** and scroll to the **Users** section.

    Click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter your Gmail address in **Email Addresses**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.email='your-email@gmail.com'
    uci commit luci-sso
    ```

For Google Workspace accounts, group-based mapping requires the Admin SDK and is not covered here — use email mapping instead.

---

## 4. Verify

Check that the service is active:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to Google's sign-in screen.

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
| `OIDC_DISCOVERY_FAILED` | The router cannot reach `accounts.google.com`. Check DNS and firewall rules from the router, not just from your laptop. |
| `TOKEN_EXCHANGE_FAILED` | The `redirect_uri` in UCI does not exactly match the authorized redirect URI in Google Cloud Console. Both must be identical, including scheme and path. |
| `USER_NOT_AUTHORIZED` | Authentication succeeded but the Gmail address is not in any role. Add it with `uci add_list luci-sso.admin.email='...'`. |
| Google returns "Access blocked: This app's request is invalid" | The authorized redirect URI in Google Cloud Console is missing or wrong. Double-check it matches `https://<router>/cgi-bin/luci-sso/callback`. |
| Google sign-in works but redirects back to Google | The OAuth consent screen app is in **External** mode and the signing-in account is not listed as a test user. Add it under **OAuth consent screen > Test users**. |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
