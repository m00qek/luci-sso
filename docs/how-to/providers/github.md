# How-to: Configure GitHub OAuth2

This guide describes how to use GitHub as an authentication provider for `luci-sso`.

---

## 1. GitHub Developer Setup
1.  Log in to GitHub and go to **Settings > Developer settings > OAuth Apps**.
2.  Click **New OAuth App**.
3.  **Homepage URL:** `https://<YOUR_ROUTER_IP_OR_DOMAIN>`
4.  **Authorization callback URL:** `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback`
5.  Click **Register application**.
6.  Generate a **Client Secret** and save both the **Client ID** and **Secret**.

## 2. Router Configuration

Run the following commands via SSH:

```bash
uci set luci-sso.default.issuer_url='https://github.com'
uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
uci set luci-sso.default.enabled='1'
uci commit luci-sso
```

---

## ⚠️ Known Limitation
GitHub uses **OAuth2** rather than full **OIDC**. `luci-sso` implements OIDC-compatible logic that handles GitHub's `/user` endpoint for identity extraction, but some advanced OIDC claims may not be available.
