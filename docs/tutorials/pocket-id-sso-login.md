# Your First SSO Login: Self-hosted IdP

In this tutorial, we will enable single sign-on on your OpenWrt router using [Pocket ID](https://pocket-id.org/) — a self-hosted identity provider that runs entirely on your LAN. No external accounts or public infrastructure are required; the entire login flow stays on your network.

Users authenticate with a passkey (biometric or hardware security key) instead of a password.

---

## What we will build

```
                                      ┌──────────────────────────────┐
┌──────────────────────────────┐      │ Authorization Required       │
│ Authorization Required       │      │   Username [              ]  │
│   Username [              ]  │  =>  │   Password [              ]  │
│   Password [              ]  │      │                  < Log in >  │
│                  < Log in >  │      │            — or —            │
└──────────────────────────────┘      │      < Login with SSO >      │
                                      └──────────────────────────────┘
```

The browser authenticates against Pocket ID on your LAN. No traffic leaves your network during the login flow.

---

## Before we start

We need:

- `luci-sso` installed on the router. If not, follow [How to Install luci-sso](../how-to/sysadmin/installation.md) first.
- SSH access to the router.
- Pocket ID running on a device on your LAN, with at least one user and passkey enrolled.
- **LuCI accessible over HTTPS with a certificate the browser trusts.** If using a self-signed certificate, navigate to LuCI in the browser and click through the certificate warning to trust it before continuing — the SSO callback will fail otherwise.

!!! warning "Accepting certificate warnings is a security risk"
    Clicking through a certificate warning trains users to dismiss security indicators, which makes them more vulnerable when a warning signals a real threat. A [large-scale field study](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe) found that users clicked through 70% of browser SSL warnings. If possible, use a certificate signed by a local CA rather than a bare self-signed certificate — that way users never see a warning at all.

---

## Step 1: Create an OIDC client in Pocket ID

Log in to your Pocket ID admin interface and navigate to **OIDC Clients > Create**.

| Field | Value |
| :--- | :--- |
| **Name** | `luci-router` |
| **Callback URL** | `https://192.168.1.1/cgi-bin/luci-sso/callback` |

Replace `192.168.1.1` with your router's actual LAN IP or hostname.

Save the client. Copy the generated **Client ID** and **Client Secret**.

---

## Step 2: Configure luci-sso

SSH into the router and run the following commands, replacing the placeholders with your Pocket ID instance URL and the credentials from Step 1:

```bash
uci set luci-sso.default.issuer_url='https://id.example.com'
uci set luci-sso.default.client_id='YOUR_CLIENT_ID'
uci set luci-sso.default.client_secret='YOUR_CLIENT_SECRET'
uci set luci-sso.default.redirect_uri='https://192.168.1.1/cgi-bin/luci-sso/callback'
uci set luci-sso.default.scope='openid profile email'
uci set luci-sso.default.clock_tolerance='60'
uci set luci-sso.default.enabled='1'

uci add_list luci-sso.admin.email='your-email@example.com'

uci commit luci-sso
```

The `issuer_url` is the base URL of your Pocket ID instance. The `redirect_uri` must exactly match the callback URL entered in Step 1.

---

## Step 3: Confirm the service is running

```bash
curl -sk https://192.168.1.1/cgi-bin/luci-sso?action=enabled
```

Expected response:

```json
{"enabled": true}
```

If we see `{"enabled": false}`, verify that `uci commit luci-sso` ran without errors:

```bash
uci show luci-sso.default.enabled
# Should output: luci-sso.default.enabled='1'
```

---

## Step 4: See the SSO button

Navigate to `https://192.168.1.1/cgi-bin/luci/`. The login page should show a "Login with SSO" button above the standard fields.

![LuCI login page showing the standard username and password fields, with a blue "Login with SSO" button prominently displayed above them](../assets/screenshots/luci-login-sso-button.svg "LuCI login page with the SSO button enabled")

If the button is not there, clear the browser cache and reload. If it still does not appear, check the system log:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -20
    ```

---

## Step 5: Log in

Click **Login with SSO**. The browser redirects to the Pocket ID login page. Authenticate with your passkey.

After authenticating, Pocket ID redirects back to the router. The router exchanges the authorization code for tokens, validates them, matches the email to the `admin` role, and issues a LuCI session.

![LuCI dashboard showing the System Status page after a successful SSO login. The sidebar shows Status, System, Network, and Services menus all expanded. The top bar shows the logged-in email address and role.](../assets/screenshots/luci-admin-view.svg "LuCI dashboard — logged in via SSO with admin role")

---

## What we just built

- Pocket ID authenticates users with passkeys; the router never sees a password.
- The entire login flow is contained within the LAN — no external services are involved.
- The authorization code is short-lived and bound to a PKCE verifier — it cannot be replayed.
- The email is matched to the `admin` role, granting full read and write access to LuCI.
- The standard username/password login still works at `/cgi-bin/luci/admin/` as a fallback.

---

## Next steps

- Restrict access or add more users: [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md)
- Map access by group instead of email: [How to Configure Pocket ID](../how-to/providers/pocket-id.md)
- Try a public IdP: [Your First SSO Login: Public IdP](first-sso-login.md)
- Understand what happened under the hood: [About the OIDC Login Flow](../explanation/oidc-flow.md)
