# UCI Configuration Reference

The configuration for `luci-sso` is stored in `/etc/config/luci-sso`.

---

## 🔑 OIDC Section (`config oidc 'default'`)

| Option | Type | Description |
| :--- | :--- | :--- |
| `enabled` | boolean | Must be set to `1` to activate the service. |
| `issuer_url` | string (URL) | The logical OIDC issuer identifier (MUST use `https://`). |
| `internal_issuer_url` | string (URL) | (Optional) The physical URL used by the router to reach the IdP. |
| `client_id` | string | The Client ID registered with your IdP. |
| `client_secret` | string | The Client Secret registered with your IdP. |
| `redirect_uri` | string (URL) | Must match exactly what is configured in your IdP. |
| `scope` | string | Space-separated list of scopes (e.g., `openid profile email`). |
| `clock_tolerance` | integer | **Required.** Allowed clock skew in seconds for JWT validation. Valid range: `0`–`3600`. The shipped default configuration sets this to `60`. |

## 👥 Role Mapping (`config role`)

A user is assigned a role if ANY of its conditions match (Logical OR).

| Option | Type | Description |
| :--- | :--- | :--- |
| `email` | list (string) | Match by OIDC email address(es). |
| `group` | list (string) | Match by OIDC group(s). |
| `read` | list (string) | List of LuCI access groups for read access. Use `*` for all. |
| `write` | list (string) | List of LuCI access groups for write access. Use `*` for all. |

---

## 📝 Example Configuration

```properties
config oidc 'default'
    option enabled '1'
    option issuer_url 'https://auth.example.com/realms/homelab'
    option client_id 'luci-router'
    option client_secret 'YOUR_SECRET_HERE'
    option redirect_uri 'https://192.168.1.1/cgi-bin/luci-sso/callback'
    option scope 'openid profile email'
    option clock_tolerance '60'

config role 'admin'
    list email 'admin@example.com'
    list group 'admins'
    list read '*'
    list write '*'
```
