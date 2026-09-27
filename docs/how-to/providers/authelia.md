# How to Configure Authelia

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
  token_endpoint_auth_method: client_secret_post
```

`luci-sso` sends the client secret in the token request body, so the client must accept `client_secret_post`.

Reload Authelia after saving the configuration.

---

## 2. Configure the router

The **Client Secret** is the **plaintext** secret — Authelia stores the hash, but the router presents the plaintext during token exchange.

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**.

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

    Navigate to **Services > Single Sign-On** and scroll to the **Users** section.

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

    Navigate to **Services > Single Sign-On** and scroll to the **Users** section.

    Click **Edit** on the `admin` role (or **Add** to create it). In the modal, enter the group name in **Groups**, then click **Save**.

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.admin.group='router-admins'
    uci commit luci-sso
    ```

---

## 4. Verify

Check that the service is active. On the router:

--8<-- "probe-enabled.md"

Navigate to the LuCI login page. The **Login with SSO** button should appear. Clicking it redirects to your Authelia instance.

---

## Troubleshooting

--8<-- "check-log.md"

| Symptom | Likely cause |
| :--- | :--- |
| `[502] OIDC_DISCOVERY_FAILED`, preceded by `Discovery fetch failed for [id: …]: …` | The router cannot reach `auth.example.com`; the end of the line names the cause. Test from the router with `uclient-fetch -q -O - 'https://auth.example.com/.well-known/openid-configuration'`. If the line ends in `HTTP_REQUEST_FAILED (CERT_UNTRUSTED)`, the router does not trust Authelia's certificate; see [How to Install a Private CA Certificate](../sysadmin/install-ca-certificate.md). |
| `[502] OIDC_DISCOVERY_FAILED`, preceded by `DISCOVERY_ISSUER_MISMATCH: issuer_url is "…" but the discovery document declares "…"` | `issuer_url` differs from the issuer Authelia declares. Copy the declared value into `issuer_url`. |
| `[500] CONFIG_ERROR`, preceded by `Configuration rejected: redirect_uri is mandatory and must use HTTPS` | `redirect_uri` was never saved. Set it with `uci set luci-sso.default.redirect_uri='https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback'` and `uci commit luci-sso`. Other `Configuration rejected` reasons name the option to fix. |
| Authelia shows an error page instead of its login screen | The `redirect_uri` in UCI does not exactly match a `redirect_uris` entry in Authelia's client config. The router logs no `OIDC callback received` line. |
| `[502] TOKEN_EXCHANGE_FAILED`, preceded by `Token exchange HTTP 401` | Authelia rejected the client credentials: the client secret is wrong (UCI needs the plaintext, Authelia the hash), or the client does not accept `client_secret_post`. |
| `UserInfo fallback failed [session_id: …]: USERINFO_INVALID_JSON`, then `[403] USER_NOT_AUTHORIZED` | Authelia returned a signed UserInfo response, which `luci-sso` cannot read, so the email and groups it carries are lost. Set `userinfo_signed_response_alg: none` on the client and reload Authelia. |
| `[403] USER_NOT_AUTHORIZED`, preceded by `User [sub_id: …] matched no roles` | The user's email or group does not match any configured role. Email matching ignores case; group matching is case-sensitive, so check the group name exactly. |

For a full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md). For every check `luci-sso` makes of an identity provider, and the error each failure logs, see [Provider Compatibility](../../reference/provider-compatibility.md).
