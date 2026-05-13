# How to Debug luci-sso

This guide describes how to troubleshoot authentication failures in `luci-sso`.

---

## 🔍 System Logs
All security events and authentication traces are logged to syslog. Use `logread` to view them:

```bash
logread -e luci-sso
```

### Common Log Messages

| Code | Likely cause |
| :--- | :--- |
| `SYSTEM_INIT_FAILED` | `/etc/luci-sso` directory permissions are wrong or the crypto backend failed to initialize. |
| `OIDC_DISCOVERY_FAILED` | The router cannot reach the `issuer_url`. Check DNS and firewall rules. |
| `SSL_INIT_FAILED` | The router does not trust the IdP's TLS certificate. Run `opkg install ca-bundle` or add your CA to `/etc/ssl/certs`. |
| `NO_ROLES_MATCHED` | Authentication succeeded but the user's email/groups don't match any UCI role. |
| `STATE_MISMATCH` | Browser lost the handshake cookie, or a CSRF attempt was blocked. |

For the full list of every error code and what triggers it, see the [Log Messages Reference](../../reference/log-messages.md).

## 🧪 Testing the Endpoint
You can check if the SSO service is logically enabled and reachable by visiting:

```text
https://<YOUR_ROUTER_IP>/cgi-bin/luci-sso?action=enabled
```

It should return `{"enabled":true}` if the service is correctly configured and enabled in UCI.

---

## 🛡️ Security Note
When sharing logs for troubleshooting, **always redact sensitive information** like tokens or IP addresses that might be specific to your internal network.
