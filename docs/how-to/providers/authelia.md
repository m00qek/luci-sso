# How-to: Configure Authelia

This guide describes how to connect `luci-sso` to an [Authelia](https://www.authelia.com/) instance.

---

## 1. Register an OIDC client in Authelia

Add a new client to your Authelia `configuration.yml` under `identity_providers.oidc.clients`. Generate a hashed secret with `authelia hash-password` and use the hash (not the plaintext) in the config:

```yaml
- id: luci-router
  description: OpenWrt Router
  secret: '$pbkdf2-sha512$310000$...'  # authelia hash-password <your-secret>
  public: false
  authorization_policy: one_factor
  redirect_uris:
    - https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback
  scopes:
    - openid
    - profile
    - email
    - groups
  userinfo_signed_response_alg: none
```

Reload Authelia after saving the configuration.

---

## 2. Configure the router

The **Client Secret** is the **plaintext** secret — Authelia stores the hash, but the router presents the plaintext during token exchange.

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**.

    Fill in the **Settings** section:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://auth.example.com` |
    | **Client ID** | `luci-router` |
    | **Client Secret** | Your plaintext secret |
    | **Redirect URI** | `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback` |
    | **Scopes** | `openid profile email groups` |
    | **Clock Tolerance** | `60` |

    The Redirect URI must exactly match the value in the Authelia client config.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://auth.example.com'
    uci set luci-sso.default.client_id='luci-router'
    uci set luci-sso.default.client_secret='<YOUR_PLAINTEXT_SECRET>'
    uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'
    uci set luci-sso.default.scope='openid profile email groups'
    uci set luci-sso.default.clock_tolerance='60'
    uci set luci-sso.default.enabled='1'
    uci commit luci-sso
    ```

    The `redirect_uri` must exactly match the value in the Authelia client config.

---

## 3. Configure role mapping

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

Authelia returns LDAP/AD group memberships in the `groups` claim. The group name must exactly match the name as Authelia returns it (case-sensitive).

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

## 4. Verify

Check that the service is active:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to your Authelia instance.

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
| `OIDC_DISCOVERY_FAILED` | The router cannot reach `auth.example.com`. Test with `curl -s https://auth.example.com/.well-known/openid-configuration` from the router. If the IdP uses a private CA, see [How to Install a Private CA Certificate](../sysadmin/install-ca-certificate.md). |
| `TOKEN_EXCHANGE_FAILED` | The `redirect_uri` in UCI does not exactly match the `redirect_uris` entry in Authelia's client config, or the client secret is wrong. |
| `USER_NOT_AUTHORIZED` with "matched no roles" | The user's email or group does not match any configured role. If using group mapping, verify the group name is an exact case-sensitive match. |
| Authelia returns an error about `userinfo_signed_response_alg` | The Authelia client config is missing `userinfo_signed_response_alg: none`. Add it and reload Authelia. |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
