# Debugging & Logs

This guide describes how to troubleshoot authentication failures in `luci-sso`.

---

## 🔍 System Logs
All security events and authentication traces are logged to syslog. Use `logread` to view them:

```bash
logread -e luci-sso
```

### Common Log Messages
*   `SYSTEM_INIT_FAILED`: The `/etc/luci-sso` directory permissions are wrong or the crypto backend failed to initialize.
*   `OIDC_DISCOVERY_FAILED`: The router cannot reach the `issuer_url`. Check DNS and Firewall settings.
*   `SSL_INIT_FAILED`: The router does not trust the IdP's SSL certificate. Install `ca-bundle` or add your CA to `/etc/ssl/certs`.

## 🧪 Testing the Endpoint
You can check if the SSO service is logically enabled and reachable by visiting:

```text
https://<YOUR_ROUTER_IP>/cgi-bin/luci-sso?action=enabled
```

It should return `{"enabled":true}` if the service is correctly configured and enabled in UCI.

---

## 🛡️ Security Note
When sharing logs for troubleshooting, **always redact sensitive information** like tokens or IP addresses that might be specific to your internal network.
