# How to Configure Google

This guide describes how to connect `luci-sso` to Google Workspace or a personal Google Cloud project.

---

## 1. Register an OAuth client in Google Cloud

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and sign in.
2. Create a new project (or select an existing one).
3. Navigate to **APIs & Services > OAuth consent screen**. Choose **Internal** (Google Workspace only) or **External** (personal accounts). Fill in an app name and contact email, then click through to **Save and Continue**.
4. Navigate to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
   - **Application type:** Web application.
   - **Name:** `LuCI Router`.
   - **Authorized redirect URIs:** `https://<YOUR_ROUTER_DOMAIN>/cgi-bin/luci-sso/callback`.
5. Click **Create**. Copy the generated **Client ID** and **Client Secret**.

Google rejects redirect URIs whose host is an IP address or does not end in a public domain (so `router.lan` does not work). Use a name under a domain you own; it only has to resolve for your browsers, for example through the LAN's DNS.

!!! note "External apps and test users"
    If you chose **External** on the OAuth consent screen, Google restricts sign-in to accounts listed as test users until the app is verified. Add your Gmail address under **OAuth consent screen > Test users** before proceeding.

---

## 2. Configure the router

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://accounts.google.com` |
    | **Client ID** | Your Client ID from Step 1 |
    | **Client Secret** | Your Client Secret from Step 1 |
    | **Redirect URI** | `https://<YOUR_ROUTER_DOMAIN>/cgi-bin/luci-sso/callback` |
    | **Scopes** | `openid profile email` |
    | **Clock Tolerance** | `60` |

    The Redirect URI must exactly match the authorized redirect URI registered in Step 1.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://accounts.google.com'
    uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
    uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_DOMAIN>/cgi-bin/luci-sso/callback'
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

    Navigate to **Services > Single Sign-On** and scroll to the **Users** section.

    Click **Edit** on the `admin` role. (If it is gone, type `admin` next to **Add**, click **Add**, and put `*` in **Read Access** and **Write Access**.) In the modal, enter your Gmail address in **Email Addresses**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.email='your-email@gmail.com'
    uci commit luci-sso
    ```

For Google Workspace accounts, group-based mapping requires the Admin SDK and is not covered here — use email mapping instead.

---

## 4. Verify

Check that the service is active. On the router:

--8<-- "probe-enabled.md"

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to Google's sign-in screen.

---

## Troubleshooting

--8<-- "check-log.md"

| Symptom | Likely cause |
| :--- | :--- |
| `[502] OIDC_DISCOVERY_FAILED`, preceded by `Discovery fetch failed for [id: …]: …` | The router cannot reach `accounts.google.com`; the end of the line names the cause. Check DNS and firewall rules from the router, not just from your laptop. |
| `[500] CONFIG_ERROR`, preceded by `Configuration rejected: redirect_uri is mandatory and must use HTTPS` | `redirect_uri` was never saved. Set it with `uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_DOMAIN>/cgi-bin/luci-sso/callback'` and `uci commit luci-sso`. Other `Configuration rejected` reasons name the option to fix. |
| `[502] TOKEN_EXCHANGE_FAILED`, preceded by `Token exchange HTTP 401` | Google rejected the client credentials. Check that `client_id` and `client_secret` are the pair from Step 1. |
| `[403] USER_NOT_AUTHORIZED`, preceded by `User [sub_id: …] matched no roles` | Authentication succeeded but the Gmail address is not in any role. Add it with `uci add_list luci-sso.admin.email='...'`. Email matching ignores case. |
| Google shows an error page, such as `redirect_uri_mismatch`, instead of the sign-in screen | The authorized redirect URI in Google Cloud Console is missing or differs from the router's `redirect_uri`. Both must be identical, including scheme and path. The router logs no `OIDC callback received` line, because Google never sends the browser back. |
| Google shows "Access blocked" for an account | The OAuth consent screen app is in **External** mode and the account is not listed as a test user. Add it under **OAuth consent screen > Test users**. |
| **Log out** in LuCI leaves you signed in to Google | Expected. Google's discovery document has no `end_session_endpoint`, so **Log out** ends only the router session; the next **Login with SSO** may complete without asking for a password. Sign out of Google to end that session. |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md). For every check `luci-sso` makes of an identity provider, and the error each failure logs, see [Provider Compatibility](../../reference/provider-compatibility.md).
