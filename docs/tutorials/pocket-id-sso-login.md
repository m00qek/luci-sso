# Your First SSO Login: Self-hosted IdP

In this tutorial, we will enable single sign-on on your OpenWrt router using [Pocket ID](https://pocket-id.org/) — a self-hosted identity provider (IdP), the service that checks who the user is and tells the router, running entirely on your LAN. No external accounts or public infrastructure are required; the entire login flow stays on your network.

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
- Pocket ID running on a device on your LAN, with at least one user and passkey enrolled. This tutorial was checked against Pocket ID 2.16.0.
- **The router trusting Pocket ID's certificate.** The router connects to Pocket ID itself, over HTTPS. If Pocket ID's certificate comes from a private CA, install that CA on the router first: [How to Install a Private CA Certificate](../how-to/sysadmin/install-ca-certificate.md).
- **LuCI accessible over HTTPS with a certificate the browser trusts.** If using a self-signed certificate, navigate to LuCI in the browser and click through the certificate warning to trust it before continuing — the SSO callback will fail otherwise.

!!! warning "Accepting certificate warnings is a security risk"
    Clicking through a certificate warning trains users to dismiss security indicators, which makes them more vulnerable when a warning signals a real threat. If possible, use a certificate signed by a local CA rather than a bare self-signed certificate — that way users never see a warning at all.

---

## Step 1: Create an OIDC client in Pocket ID

Log in to Pocket ID as an administrator and open **Administration > OIDC Clients**. Click **Add OIDC Client**.

| Field | Value |
| :--- | :--- |
| **Name** | `luci-router` |
| **Callback URLs** | Click **Add**, then enter `https://192.168.1.1/cgi-bin/luci-sso/callback` |
| **Logout Callback URLs** | Click **Add**, then enter `https://192.168.1.1/` |

Replace `192.168.1.1` with your router's actual LAN IP or hostname. Leave the switches below them off.

![Pocket ID Create OIDC Client form. Name is luci-router. Callback URLs holds a callback URL ending in /cgi-bin/luci-sso/callback and Logout Callback URLs holds the router's address, each added with the Add button. The Public Client, PKCE, Requires Re-Authentication and Skip Consent Screen switches are off.](../assets/screenshots/idp/pocket-id-client-form.png "Create OIDC Client with both callback URLs added")

Click **Save**. Pocket ID opens the client's page. Copy the **Client ID** shown at the top.

Open the **Credentials** tab and click **Add client secret**. Copy the secret it shows; Pocket ID hides it once we leave the page.

Open the **Allowed User Groups** tab and click **Unrestrict**, then confirm. A new client lets no one sign in until we do this. The router's `admin` role, set up in the next step, decides who gets in.

The router matches us by our email address, and it trusts only an address Pocket ID marks as verified. Pocket ID does not mark addresses an administrator entered. Open **Administration > Users** and edit our user. Next to **Email** is an envelope button, yellow while the address is unverified. Click it (**Mark as verified**) so that it turns green, then save the user.

---

## Step 2: Configure luci-sso

Navigate to **Services > Single Sign-On**.

Fill in the **Settings** section with the values from Step 1:

| Field | Value |
| :--- | :--- |
| **Enable SSO** | On |
| **Issuer URL** | `https://id.example.com` |
| **Client ID** | Our Client ID from Step 1 |
| **Client Secret** | Our Client Secret from Step 1 |
| **Redirect URI** | `https://192.168.1.1/cgi-bin/luci-sso/callback` |
| **Scopes** | `openid profile email` |
| **Clock Tolerance** | `60` |

Replace `https://id.example.com` with our Pocket ID's `APP_URL`, exactly as it is set there, with no trailing slash. The **Redirect URI** field suggests a callback URL built from the address in our browser; we make sure it is exactly the callback URL we set in Step 1.

Scroll to the **Users** section and click **Edit** on the `admin` role. In **Email Addresses**, remove the placeholder `admin@example.com`, add our email address, and click **Save**.

Click **Save & Apply**.

!!! note "Prefer the command line?"
    The same configuration can be done over SSH. See [How to Configure Pocket ID](../how-to/providers/pocket-id.md) for the UCI equivalents.

---

## Step 3: Confirm the service is running

In the browser, we open:

```text
https://192.168.1.1/cgi-bin/luci-sso?action=enabled
```

Expected response:

```json
{"enabled": true}
```

If we see `{"enabled": false}`, verify that **Enable SSO** is toggled on in **Services > Single Sign-On** and that we clicked **Save & Apply**.

If we get an error page instead, SSO is on but the configuration is incomplete. The system log (**Status > System Log**) has a line starting `Configuration rejected:` that names the option. If it says `redirect_uri is mandatory and must use HTTPS`, re-check the Redirect URI in **Services > Single Sign-On** and **Save & Apply** again. We can also set it over SSH:

```bash
uci set luci-sso.default.redirect_uri='https://192.168.1.1/cgi-bin/luci-sso/callback'
uci commit luci-sso
```

---

## Step 4: See the SSO button

Navigate to `https://192.168.1.1/cgi-bin/luci/`. The login page should show a "Login with SSO" button below the **Log in** button.

!!! warning "Use the same host name as the Redirect URI"
    Open LuCI at the same address as in the Redirect URI, here `192.168.1.1`. If the Redirect URI uses a host name instead, open LuCI at that name. The login starts at whatever address the browser shows, and its cookie is only sent back to that exact host, so a login started at one address fails when Pocket ID returns to another.

![LuCI login page: an Authorization Required box with Username and Password fields and a green Log in button, followed by "— or —" and a green Login with SSO button](../assets/screenshots/luci-login-sso-button.png "The LuCI login page with the Login with SSO button")

If the button is not there, clear the browser cache and reload. If it still does not appear, check the system log:

--8<-- "check-log.md"

---

## Step 5: Log in

Click **Login with SSO**. The browser opens Pocket ID's "Sign in to luci-router" page. Click **Sign in** and authenticate with your passkey. The first time, Pocket ID lists the information the router asks for (email and profile); click **Sign in** again to approve.

After authenticating, Pocket ID redirects back to the router. The router exchanges the authorization code for tokens, validates them, matches the email to the `admin` role, and issues a LuCI session.

![LuCI Status > Overview page after an SSO login with the admin role. The top bar shows the router's hostname and the Status, System, Services and Network menus and Log out. The System table lists hostname, model, architecture, target platform, firmware and kernel versions, local time, uptime and load average.](../assets/screenshots/luci-admin-view.png "Status > Overview after an SSO login with the admin role")

---

## What we just built

- Pocket ID authenticates users with passkeys; the router never sees a password.
- The entire login flow is contained within the LAN — no external services are involved.
- The authorization code is short-lived and bound to a PKCE verifier — it cannot be replayed.
- The email is matched to the `admin` role, granting full read and write access to LuCI.
- LuCI's **Log out** also ends the Pocket ID session, so the next SSO login asks for the passkey again.
- The standard username/password login still works at `/cgi-bin/luci/admin/` as a fallback.

---

## Next steps

- Restrict access or add more users: [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md)
- Map access by group instead of email: [How to Configure Pocket ID](../how-to/providers/pocket-id.md)
- Try a public IdP: [Your First SSO Login: Public IdP](first-sso-login.md)
- Understand what happened under the hood: [About the OIDC Login Flow](../explanation/oidc-flow.md)
