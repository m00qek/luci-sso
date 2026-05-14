# How to Install a Private CA Certificate

This guide describes how to make the router trust a private or self-signed CA certificate — required when your identity provider uses a certificate that is not signed by a publicly trusted authority.

---

## When you need this

If your IdP uses a certificate issued by a private CA (common in home labs and corporate self-hosted setups), the router will fail the back-channel TLS handshake and log `SSL_INIT_FAILED` or `TOKEN_ENDPOINT_NETWORK_ERROR`. Installing the CA certificate on the router resolves this.

You do not need this guide if your IdP uses a Let's Encrypt or other publicly trusted certificate.

---

## Prerequisites

- SSH access to the router.
- Your CA certificate in **PEM format** (a `.crt` or `.pem` file beginning with `-----BEGIN CERTIFICATE-----`).
- The `ca-bundle` package installed on the router. If it is not, install it first:

```bash
opkg update && opkg install ca-bundle
```

---

## Step 1: Copy the certificate to the router

From your local machine, copy the CA certificate to the router's certificate directory:

```bash
scp -O /path/to/my-ca.crt root@192.168.1.1:/etc/ssl/certs/my-ca.crt
```

Replace `my-ca.crt` with a descriptive name for the CA (e.g., `homelab-ca.crt`). The name does not affect trust — only the file's presence matters.

---

## Step 2: Update the CA bundle

Run this command on the router to rebuild the trusted certificate store:

```bash
update-ca-certificates
```

You should see output confirming the certificate was added:

```
Updating certificates in /etc/ssl/certs...
1 added, 0 removed; done.
```

---

## Step 3: Verify the certificate is trusted

Test that the router now trusts your IdP's certificate. Replace `<issuer_url>` with your configured issuer URL:

```bash
curl -s https://<YOUR_ISSUER_URL>/.well-known/openid-configuration
```

If the command returns a JSON document, the certificate is trusted. If it returns a certificate error, double-check that:

1. The certificate you copied is the **CA** certificate (the issuer), not the IdP's server certificate.
2. The file is valid PEM — open it and confirm it begins with `-----BEGIN CERTIFICATE-----`.
3. `update-ca-certificates` was run after copying the file.

---

## Step 4: Confirm luci-sso can reach the IdP

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Then attempt a login. If you previously saw `SSL_INIT_FAILED` in the log, it should no longer appear.

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -20
    ```

---

## Removing the certificate

If you later remove `luci-sso` or switch to a publicly trusted IdP, remove the certificate and rebuild the store:

```bash
rm /etc/ssl/certs/my-ca.crt
update-ca-certificates
```

---

## Related guides

- [How to Configure Split-Horizon Networking](split-horizon.md) — if the router and browser reach the IdP at different addresses, you may need both this guide and split-horizon configuration.
- [How to Debug luci-sso](debugging.md) — for diagnosing `SSL_INIT_FAILED` and other TLS errors.
