# How-to: Configure Authelia

This guide describes how to connect `luci-sso` to an [Authelia](https://www.authelia.com/) instance.

---

## 1. Authelia Configuration
Add a new client to your Authelia `configuration.yml` under `identity_providers: oidc: clients`:

```yaml
- id: luci-router
  description: OpenWrt Router
  secret: '$pbkdf2-sha512$310000$...' # Use authelia hash-password to generate
  public: false
  authorization_policy: one_factor
  redirect_uris:
    - https://192.168.1.1/cgi-bin/luci-sso/callback
  scopes:
    - openid
    - profile
    - email
    - groups
  userinfo_signed_response_alg: none
```

## 2. Router Configuration

!!! note
    Router configuration is not yet available in the LuCI web interface. Use SSH for the steps below.

```bash
uci set luci-sso.default.issuer_url='https://auth.example.com'
uci set luci-sso.default.client_id='luci-router'
uci set luci-sso.default.client_secret='YOUR_SECRET_HERE'
uci set luci-sso.default.enabled='1'
uci commit luci-sso
```

---

## 👥 Group Mapping

!!! note
    Role configuration is not yet available in the LuCI web interface. Use SSH for the steps below.

Authelia allows you to map LDAP/AD groups to LuCI roles. Ensure you map the `groups` claim in your `config role`:

```bash
uci add_list luci-sso.admin.group='router-admins'
uci commit luci-sso
```

## ✅ Verify

Visit `https://<YOUR_ROUTER_IP>/cgi-bin/luci-sso?action=enabled` — it should return `{"enabled":true}`. Then navigate to the LuCI login page and confirm the "Login with SSO" button appears. Clicking it should redirect you to your Authelia instance.
