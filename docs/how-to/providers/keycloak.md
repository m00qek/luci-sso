# How-to: Configure Keycloak

This guide describes how to connect `luci-sso` to a [Keycloak](https://www.keycloak.org/) instance.

---

## 1. Create an OIDC client in Keycloak

Log in to your Keycloak admin console and select the realm you want to use (or create a new one).

Navigate to **Clients > Create client**.

| Field | Value |
| :--- | :--- |
| **Client type** | `OpenID Connect` |
| **Client ID** | `luci-router` (or any label you prefer) |

Click **Next**. On the Capability config screen:

| Field | Value |
| :--- | :--- |
| **Client authentication** | On (this makes the client confidential) |
| **Authorization** | Off |

Click **Next**. On the Login settings screen:

| Field | Value |
| :--- | :--- |
| **Valid redirect URIs** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |

Click **Save**.

Go to the **Credentials** tab of the newly created client and copy the **Client Secret**.

---

## 2. Find your issuer URL

The issuer URL includes the realm name. In the Keycloak admin console, navigate to **Realm settings** — the issuer URL is displayed there, or construct it as:

```
https://<YOUR_KEYCLOAK_HOST>/realms/<YOUR_REALM_NAME>
```

Verify the discovery document is reachable before proceeding:

```bash
curl -s https://<YOUR_KEYCLOAK_HOST>/realms/<YOUR_REALM_NAME>/.well-known/openid-configuration
```

---

## 3. Configure the router

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://<YOUR_KEYCLOAK_HOST>/realms/<YOUR_REALM_NAME>` |
    | **Client ID** | `luci-router` |
    | **Client Secret** | Your Client Secret from Step 1 |
    | **Redirect URI** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |
    | **Scopes** | `openid profile email` |

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://<YOUR_KEYCLOAK_HOST>/realms/<YOUR_REALM_NAME>'
    uci set luci-sso.default.client_id='luci-router'
    uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'
    uci set luci-sso.default.scope='openid profile email'
    uci set luci-sso.default.enabled='1'
    uci commit luci-sso
    ```

---

## 4. Configure role mapping

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

Keycloak can include group membership in the `groups` claim, but this requires adding a mapper to the client. In the Keycloak admin console:

1. Open the client you created in Step 1.
2. Go to **Client scopes** and click on the dedicated scope (usually named `luci-router-dedicated`).
3. Click **Add mapper > By configuration > Group Membership**.
4. Set **Token Claim Name** to `groups` and disable **Full group path** (so claims contain `my-group`, not `/my-group`).
5. Save the mapper.

Then enable the `groups` scope on the router and map the group:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**.

    In **Settings**, update **Scopes** to `openid profile email groups` and click **Save & Apply**.

    Scroll to **Users**, click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the group name in **Groups**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.scope='openid profile email groups'
    uci add_list luci-sso.admin.group='router-admins'
    uci commit luci-sso
    ```

---

## 5. Verify

Check that the service is active:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to your Keycloak login screen.

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
| `DISCOVERY_ISSUER_MISMATCH` | The realm name in `issuer_url` does not match exactly. Copy the `issuer` field directly from `/.well-known/openid-configuration` and use that value. |
| `TOKEN_EXCHANGE_FAILED` | **Client authentication** was left off when creating the client — the client is public, not confidential. Re-create the client with **Client authentication: On**. |
| `USER_NOT_AUTHORIZED` with "matched no roles" | Group mapping is missing or the mapper has **Full group path** enabled, so the claim contains `/my-group` instead of `my-group`. Either disable Full group path in the mapper or update the role config to match the full path. |
| `SSL_INIT_FAILED` | The router does not trust Keycloak's TLS certificate. See [How to Install a Private CA Certificate](../sysadmin/install-ca-certificate.md). |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
