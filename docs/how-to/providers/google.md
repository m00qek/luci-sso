# How-to: Configure Google OIDC

This guide describes how to connect `luci-sso` to Google Workspace or a personal Google Cloud project.

---

## 1. Google Cloud Console Setup
1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Create a new project (or select an existing one).
3.  Navigate to **APIs & Services > OAuth consent screen**. Configure it for "Internal" or "External" use.
4.  Navigate to **Credentials > Create Credentials > OAuth client ID**.
    *   **Application type:** Web application.
    *   **Name:** LuCI Router.
    *   **Authorized redirect URIs:** `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback`.
5.  Save the **Client ID** and **Client Secret**.

## 2. Router Configuration

!!! note
    Router configuration is not yet available in the LuCI web interface. Use SSH for the steps below.

```bash
uci set luci-sso.default.issuer_url='https://accounts.google.com'
uci set luci-sso.default.client_id='<YOUR_CLIENT_ID>'
uci set luci-sso.default.client_secret='<YOUR_CLIENT_SECRET>'
uci set luci-sso.default.enabled='1'
uci commit luci-sso
```

---

## 🛡️ Role Mapping

!!! note
    Role configuration is not yet available in the LuCI web interface. Use SSH for the steps below.

To grant yourself admin access, ensure your OIDC email is mapped to the admin role:

```bash
uci add_list luci-sso.admin.email='your-email@gmail.com'
uci commit luci-sso
```

## ✅ Verify

Visit `https://<YOUR_ROUTER_IP>/cgi-bin/luci-sso?action=enabled` — it should return `{"enabled":true}`. Then navigate to the LuCI login page and confirm the "Login with SSO" button appears. Clicking it should redirect you to Google's consent screen.
