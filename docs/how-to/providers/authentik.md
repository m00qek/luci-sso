# How-to: Configure Authentik

This guide describes how to connect `luci-sso` to an [Authentik](https://goauthentik.io/) instance.

Authentik uses a two-step setup: you create a **Provider** (the OAuth2/OIDC configuration) and then an **Application** that exposes it. Both are required.

---

## 1. Create an OAuth2/OpenID Connect provider

Log in to your Authentik admin interface and navigate to **Applications > Providers > Create**.

Select **OAuth2/OpenID Provider** and fill in the following:

| Field | Value |
| :--- | :--- |
| **Name** | `luci-router` |
| **Client type** | `Confidential` |
| **Redirect URIs/Origins** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |
| **Signing Key** | Select your existing signing key (usually `authentik Self-signed Certificate`) |

Leave the remaining fields at their defaults and click **Finish**.

Copy the generated **Client ID** and **Client Secret** from the provider detail page.

---

## 2. Create an Application

Navigate to **Applications > Applications > Create**.

| Field | Value |
| :--- | :--- |
| **Name** | `LuCI Router` |
| **Slug** | `luci-router` (used in the issuer URL) |
| **Provider** | Select the provider created in Step 1 |

Click **Create**. The slug you set here becomes part of the issuer URL.

---

## 3. Find your issuer URL

The issuer URL for Authentik includes the application slug and **requires a trailing slash**:

```
https://<YOUR_AUTHENTIK_HOST>/application/o/<APPLICATION_SLUG>/
```

Using the slug `luci-router` from Step 2:

```
https://authentik.example.com/application/o/luci-router/
```

Verify the discovery document is reachable:

```bash
curl -s 'https://authentik.example.com/application/o/luci-router/.well-known/openid-configuration'
```

---

## 4. Configure the router

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://authentik.example.com/application/o/luci-router/` |
    | **Client ID** | Your Client ID from Step 1 |
    | **Client Secret** | Your Client Secret from Step 1 |
    | **Redirect URI** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |
    | **Scopes** | `openid profile email` |

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://authentik.example.com/application/o/luci-router/'
    uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
    uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'
    uci set luci-sso.default.scope='openid profile email'
    uci set luci-sso.default.enabled='1'
    uci commit luci-sso
    ```

---

## 5. Configure role mapping

### Map by email

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login** and scroll to the **Users** section.

    Click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the email address in **Email Addresses**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.email='user@example.com'
    uci commit luci-sso
    ```

### Map by group

Authentik includes group names in the `groups` claim via the default **authentik default OAuth Mapping: OpenID 'profile'** scope. Ensure this scope is selected in your provider's **Advanced protocol settings > Scopes**.

Authentik delivers group memberships through the `profile` scope, so no separate `groups` scope is required (it is already set in Step 4). The group name must exactly match the group name in Authentik (case-sensitive).

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login** and scroll to the **Users** section.

    Click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the group name in **Groups**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.group='router-admins'
    uci commit luci-sso
    ```

---

## 6. Verify

Check that the service is active:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to your Authentik login screen.

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
| `DISCOVERY_ISSUER_MISMATCH` | The `issuer_url` must end with a trailing slash and match the application slug exactly. Fetch the discovery document and copy the `issuer` field verbatim. |
| `OIDC_DISCOVERY_FAILED` | The application slug in the URL is wrong, or the Application was not created (only the Provider). Verify both the Provider and Application exist in Authentik. |
| `USER_NOT_AUTHORIZED` with "matched no roles" | The `groups` claim is empty. In the Authentik provider settings, confirm the **profile** scope is selected under **Advanced protocol settings > Scopes**, and that the user belongs to the mapped group. |
| `SSL_INIT_FAILED` | The router does not trust Authentik's TLS certificate. See [How to Install a Private CA Certificate](../sysadmin/install-ca-certificate.md). |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
