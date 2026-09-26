# How to Configure Split-Horizon Networking

This guide covers configuring `luci-sso` when your router and your browser reach the identity provider at different network addresses — a common setup in home labs and self-hosted environments.

---

## When you need this

Split-horizon applies when:

- Your IdP runs behind a reverse proxy or has a public hostname (e.g., `auth.homelab.local`) that the router cannot resolve, but your browser can.
- Your router must reach the IdP via an internal IP or a different port (e.g., `192.168.2.10:8443`).
- Your IdP's DNS name is only resolvable from your LAN, but your router uses a different DNS server or sits on a separate network segment.

```mermaid
sequenceDiagram
    participant B as Browser
    participant I as Identity Provider
    participant R as Router (luci-sso)

    note over B,I: Front-channel<br/>browser → auth.homelab.local
    B->>I: 1. Redirect to login
    I->>B: 2. Authorization code (via redirect)
    B->>R: 3. Callback with code

    note over R,I: Back-channel<br/>router → 192.168.2.10:8443
    R->>I: 4. Token exchange
    I->>R: 5. Tokens

    R->>B: 6. Session cookie
```

The browser uses the public `issuer_url` for steps 1–3. The router uses `internal_issuer_url` for the back-channel token exchange (step 4), which never involves the browser.

---

## What gets replaced

`internal_issuer_url` is an **origin**: `https://host` or `https://host:port`, with no path. When it is set, `luci-sso` replaces the origin (scheme, host and port) of the following back-channel URLs with it:

| URL | Replaced? |
| :--- | :--- |
| Token endpoint | ✅ Yes |
| JWKS endpoint | ✅ Yes |
| UserInfo endpoint | ✅ Yes |
| Discovery document fetch | ✅ Yes |
| Authorization endpoint (browser redirect) | ❌ No — the browser handles this |
| End-session (logout) endpoint (browser redirect) | ❌ No — the browser handles this |
| Any endpoint on a host other than `issuer_url`'s | ❌ No — e.g. Google's `googleapis.com` JWKS stays as published |
| `iss` claim validation | ❌ No — always checked against `issuer_url` |

Only the origin is swapped; the path and query are kept exactly. `https://auth.homelab.local/oauth/token` becomes `https://192.168.2.10:8443/oauth/token`.

This also works when `issuer_url` has a path, as with Keycloak realms or Authentik applications:

| | Public | Internal |
| :--- | :--- | :--- |
| `issuer_url` / `internal_issuer_url` | `https://kc.example.com/realms/home` | `https://10.0.0.5:8443` |
| Discovery fetch | — | `https://10.0.0.5:8443/realms/home/.well-known/openid-configuration` |
| Token endpoint | `https://kc.example.com/realms/home/protocol/openid-connect/token` | `https://10.0.0.5:8443/realms/home/protocol/openid-connect/token` |

!!! warning "The internal address must serve the same paths"
    `internal_issuer_url` with a path, query or fragment (for example `https://10.0.0.5/realms/home`) is rejected with `CONFIG_ERROR`. Give only the origin; the path comes from `issuer_url`. A reverse proxy that exposes the IdP under a *different* path internally than publicly is not supported.

The IdP's discovery document must still declare the public `issuer_url` as its `iss`. `luci-sso` validates the issuer claim against the public address regardless of the internal URL.

---

## Prerequisites

The internal address must:

- Use **HTTPS** — plain HTTP is rejected even for internal addresses.
- Have a certificate the router trusts. If the IdP uses a self-signed or private CA certificate, install it on the router:

```bash
# Copy your CA certificate to the router
scp -O ca.crt root@192.168.1.1:/etc/ssl/certs/my-homelab-ca.crt

# Update the CA bundle
update-ca-certificates
```

If the router cannot verify the IdP's certificate, the token exchange will fail with `TOKEN_ENDPOINT_NETWORK_ERROR`, and the line before it will end in `HTTP_REQUEST_FAILED (CERT_UNTRUSTED)`, or `(CERT_NAME_MISMATCH)` if the certificate does not cover the internal host name. See [How to Debug luci-sso](debugging.md) for log-based diagnosis.

---

## Configuration

Set `internal_issuer_url` alongside the standard configuration:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**.

    Fill in the **Settings** section with your standard provider credentials, then set **Internal Issuer URL** to the address the router uses to reach the IdP:

    | Field | Value |
    | :--- | :--- |
    | **Enable SSO** | On |
    | **Issuer URL** | `https://auth.homelab.local` |
    | **Client ID** | `luci-router` |
    | **Client Secret** | Your secret |
    | **Internal Issuer URL** | `https://192.168.2.10:8443` |

    Click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    # Standard configuration
    uci set luci-sso.default.issuer_url='https://auth.homelab.local'
    uci set luci-sso.default.client_id='luci-router'
    uci set luci-sso.default.client_secret='YOUR_SECRET_HERE'
    uci set luci-sso.default.enabled='1'

    # Split-horizon: the router reaches the IdP via this internal address
    uci set luci-sso.default.internal_issuer_url='https://192.168.2.10:8443'

    uci commit luci-sso
    ```

---

## Verify

After committing, confirm the back-channel is working:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled":true}
```

Then attempt a login from your browser. If the browser redirects to the IdP correctly but the router fails to exchange the code, the problem is in the back-channel. Check the log:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -30
    ```

Back-channel failures typically appear as `TOKEN_EXCHANGE_FAILED`, `OIDC_DISCOVERY_FAILED`, or `JWKS_FETCH_FAILED`. All three indicate the router cannot reach the internal address. Check:

1. The router can reach `internal_issuer_url` — test with `curl -sk <internal_issuer_url>/.well-known/openid-configuration` from the router.
2. The certificate is trusted — test with `curl -s` (without `-k`) to verify without skipping certificate checks.
3. `internal_issuer_url` is only an origin. If the log shows `Configuration rejected: internal_issuer_url must be an origin`, remove its path: the issuer's path is added automatically.
4. The internal address serves the IdP under the same paths as the public one.

For the full list of error codes, see the [Log Messages Reference](../../reference/log-messages.md).
