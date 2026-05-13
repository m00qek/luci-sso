# Your First SSO Login

In this tutorial, we will enable single sign-on on your OpenWrt router from scratch. By the end, we will have replaced the router's password prompt with a "Login with SSO" button, logged in using a Google account, and confirmed we have full admin access to LuCI.

We will use Google as the identity provider because it requires no self-hosted server — any Google account works. If you prefer a different provider, complete this tutorial first, then follow the relevant [provider guide](../how-to/providers/generic-oidc.md) to swap the IdP.

---

## What we will build

```
Before:          After:
┌──────────────┐  ┌──────────────────────────┐
│ Username     │  │                          │
│ Password     │  │  [ Login with SSO ]      │
│ [ Login ]    │  │                          │
└──────────────┘  └──────────────────────────┘
```

The password login remains available as a fallback at `/cgi-bin/luci/admin/` — SSO is additive, not a replacement.

---

## Before we start

We need:

- `luci-sso` installed on the router. If it is not installed yet, follow [How to Install luci-sso](../how-to/sysadmin/installation.md) first, then return here.
- SSH access to the router.
- A Google account and access to [Google Cloud Console](https://console.cloud.google.com/).
- The router's HTTPS address (e.g., `https://192.168.1.1`). luci-sso requires HTTPS — if your router only serves LuCI over HTTP, enable HTTPS in **System > Administration > HTTPS access** first.

---

## Step 1: Register a client with Google

We need to tell Google that our router is allowed to request user logins. This produces a Client ID and Client Secret — two strings the router will use to prove its identity to Google.

1. Open the [Google Cloud Console](https://console.cloud.google.com/) and sign in.
2. Create a new project: click the project dropdown at the top, then **New Project**. Name it anything — "Home Router" works fine.
3. In the left sidebar, go to **APIs & Services > OAuth consent screen**.
   - Choose **External** (works for personal accounts).
   - Fill in an app name (e.g., "LuCI Router") and your email address for the support and developer contact fields.
   - Leave all other fields empty and click through to **Save and Continue** on each screen.
4. Go to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
   - **Application type:** Web application.
   - **Name:** LuCI Router.
   - **Authorized redirect URIs:** add `https://<YOUR_ROUTER_IP>/cgi-bin/luci-sso/callback`, replacing `<YOUR_ROUTER_IP>` with your router's IP address or hostname.
   - Click **Create**.

Google will show a dialog with the Client ID and Client Secret.

![Google Cloud Console OAuth credentials dialog showing a newly created OAuth client. The Client ID field contains a long string ending in .apps.googleusercontent.com, and the Client Secret field contains a shorter token beginning with GOCSPX-.](../assets/screenshots/google-cloud-oauth-credentials.svg "Google Cloud Console — OAuth client credentials dialog")

Copy both values. We will use them in the next step.

---

## Step 2: Configure luci-sso

SSH into the router and run the following commands, replacing the placeholder values with the Client ID and Client Secret from Step 1, and your Google email address:

```bash
# Connect to the router
ssh root@192.168.1.1

# Configure the OIDC connection to Google
uci set luci-sso.default.issuer_url='https://accounts.google.com'
uci set luci-sso.default.client_id='YOUR_CLIENT_ID'
uci set luci-sso.default.client_secret='YOUR_CLIENT_SECRET'
uci set luci-sso.default.redirect_uri='https://192.168.1.1/cgi-bin/luci-sso/callback'
uci set luci-sso.default.scope='openid profile email'
uci set luci-sso.default.clock_tolerance='60'
uci set luci-sso.default.enabled='1'

# Grant yourself admin access
uci add_list luci-sso.admin.email='your-email@gmail.com'

# Apply
uci commit luci-sso
```

The `redirect_uri` must exactly match what we entered in Google Cloud Console. If our router is at a different IP or has a hostname, use that instead of `192.168.1.1`.

---

## Step 3: Confirm the service is running

Before opening a browser, let's verify the configuration took effect:

```bash
curl -sk https://192.168.1.1/cgi-bin/luci-sso?action=enabled
```

We should see:

```json
{"enabled": true}
```

If we see `{"enabled": false}`, check that `uci commit luci-sso` ran without errors and that `luci-sso.default.enabled` is `1`:

```bash
uci show luci-sso.default.enabled
# Should output: luci-sso.default.enabled='1'
```

---

## Step 4: See the SSO button

Open a browser and navigate to `https://<YOUR_ROUTER_IP>/cgi-bin/luci/`. The login page should now show a "Login with SSO" button above the standard username and password fields.

![LuCI login page showing the standard username and password fields, with a blue "Login with SSO" button prominently displayed above them](../assets/screenshots/luci-login-sso-button.svg "LuCI login page with the SSO button enabled")

If the button is not there, clear the browser cache and reload. If it still does not appear, check the system log:

```bash
logread -e luci-sso | tail -20
```

---

## Step 5: Log in

Click **Login with SSO**. Our browser will redirect to Google's sign-in page. Sign in with the Google account whose email we added to the `admin` role in Step 2.

After authenticating, Google redirects back to the router. The router exchanges the authorization code for tokens, validates them, matches our email to the `admin` role, and issues a LuCI session. We land on the LuCI dashboard with full admin access.

![LuCI dashboard showing the System Status page after a successful SSO login. The sidebar shows Status, System, Network, and Services menus all expanded. The top bar shows the logged-in email address and role.](../assets/screenshots/luci-admin-view.svg "LuCI dashboard — logged in via SSO with admin role")

We are in. The router now uses SSO for authentication.

---

## What we just built

- Google authenticates users; the router never sees their password.
- The authorization code that travels through the browser is short-lived and bound to a PKCE verifier on the router — it cannot be replayed.
- Our Google email is matched to the `admin` role, which grants full read and write access to all of LuCI.
- The standard username/password login still works at `/cgi-bin/luci/admin/` as a fallback.

---

## Next steps

- Add more users or restrict access: [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md)
- Use a self-hosted IdP instead of Google: [Generic OIDC Provider](../how-to/providers/generic-oidc.md)
- Understand what just happened under the hood: [About the OIDC Login Flow](../explanation/oidc-flow.md)
