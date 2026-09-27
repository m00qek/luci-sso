# How to Install a Private CA Certificate

This guide describes how to make the router trust a private or self-signed CA certificate — required when your identity provider uses a certificate that is not signed by a publicly trusted authority.

---

## When you need this

If your IdP uses a certificate issued by a private CA (common in home labs and corporate self-hosted setups), the router fails the back-channel TLS handshake. The log shows a line ending in `HTTP_REQUEST_FAILED (CERT_UNTRUSTED)`, followed by the request's error, usually `[500] OIDC_DISCOVERY_FAILED`:

```
luci-sso[1234]: Discovery fetch failed for [id: 957cfa182d5cc6db]: HTTP_REQUEST_FAILED (CERT_UNTRUSTED)
luci-sso[1234]: [500] OIDC_DISCOVERY_FAILED
```

Installing the CA certificate on the router resolves this.

You do not need this guide if your IdP uses a Let's Encrypt or other publicly trusted certificate. Those are covered by the `ca-bundle` package, which standard OpenWrt images include.

---

## Prerequisites

- SSH access to the router.
- Your CA certificate in **PEM format**: a file beginning with `-----BEGIN CERTIFICATE-----`.

---

## Step 1: Copy the certificate to the router

From your local machine, copy the CA certificate into the router's certificate directory. Give it a `.crt` extension:

```bash
scp -O /path/to/my-ca.crt root@192.168.1.1:/etc/ssl/certs/my-ca.crt
```

Replace `my-ca.crt` with a descriptive name for the CA (for example `homelab-ca.crt`). The name does not affect trust, but the extension does: `luci-sso` loads every `*.crt` and `*.pem` file in `/etc/ssl/certs/`, and `uclient-fetch`, used to check the result below, loads only `*.crt`.

There is no certificate store to rebuild. `luci-sso` reads the files in `/etc/ssl/certs/` on every request, so the certificate is used from the next login on.

---

## Step 2: Verify the certificate is trusted

On the router, fetch your IdP's discovery document. Replace the URL with your `issuer_url`, or with `internal_issuer_url` if you use [split-horizon networking](split-horizon.md):

```bash
uclient-fetch -q -O - 'https://id.example.com/.well-known/openid-configuration'
```

If the command prints a JSON document, the certificate is trusted. If it prints `SSL verify error: certificate is self-signed or not signed by a trusted CA`, check that:

1. The certificate you copied is the **CA** certificate (the issuer), not the IdP's server certificate.
2. The file is valid PEM — open it and confirm it begins with `-----BEGIN CERTIFICATE-----`.
3. The file name ends in `.crt`.

---

## Step 3: Confirm luci-sso can reach the IdP

Attempt a login. The `CERT_UNTRUSTED` line should no longer appear in the log.

--8<-- "check-log.md"

---

## Removing the certificate

If you later remove `luci-sso` or switch to a publicly trusted IdP, delete the file:

```bash
rm /etc/ssl/certs/my-ca.crt
```

---

## Related guides

- [How to Configure Split-Horizon Networking](split-horizon.md) — if the router and browser reach the IdP at different addresses, you may need both this guide and split-horizon configuration.
- [How to Debug luci-sso](debugging.md#a-back-channel-request-to-the-idp-failed) — for diagnosing `CERT_UNTRUSTED` and other back-channel errors.
