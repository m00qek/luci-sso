# luci-sso (Beta)

**Secure, Lightweight OIDC/OAuth2 Login for OpenWrt LuCI.**

> **⚠️ STATUS: PUBLIC BETA**
>
> While this codebase is passing 100+ unit/compliance tests, it is currently distributed as source. You must build the `.ipk` package for your specific router architecture using the included Dockerized toolchain.

<img width="1119" height="588" alt="image" src="https://github.com/user-attachments/assets/cbe996a7-fc25-4f63-bd91-0d57dddcab75" />

## 📖 Overview

`luci-sso` replaces the standard LuCI password prompt with an **OpenID Connect (OIDC)** flow.

### Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

### Why use this?
*   **Security First:** Full PKCE (S256) support, Strict HTTPS enforcement, Anti-Replay protection, and Token Binding.
*   **Lightweight:** Written in pure **ucode** with a tiny C bridge for crypto. No Python/Node.js/Go dependencies on the router.
*   **Native Integration:** Uses `ubus` session injection. No hacks, no proxy servers.
*   **Split-Horizon Support:** Supports environments where the Router and Browser see the IdP at different URLs (common in home labs).

---

## 🛠️ Building the Package

Since there is no upstream repository yet, you must build the `.ipk` file for your router's architecture.

### Prerequisites
*   Docker (or Podman)
*   `make`

### 1. Identify your Architecture
Find your target architecture (e.g., `x86_64`, `aarch64_generic`, `mips_24kc`). You can find this in OpenWrt under **System > Overview**.

### 2. Build via Docker
Run the following command in the project root. Replace `SDK_ARCH` with your target.

**For Raspberry Pi 4 / NanoPi (ARM64):**
```bash
make package SDK_ARCH=aarch64_generic
```

**For x86 routers (Intel/AMD):**
```bash
make package SDK_ARCH=x86-64
```

**For MIPS routers (e.g., gl-inet, Ubiquiti):**
```bash
make package SDK_ARCH=mips_24kc
```

*The build system will automatically download the correct OpenWrt SDK container and compile the package.*

### 3. Retrieve Artifacts
The compiled packages will be available in:
```text
bin/lib/<ARCH>/packages/luci-sso*.ipk
```

---

## 📦 Installation

1.  **Upload** the `.ipk` file to your router (e.g., via `scp`):
    ```bash
    scp -O bin/lib/.../luci-sso*.ipk root@192.168.1.1:/tmp/
    ```

2.  **Install** dependencies and the package:
    ```bash
    # Install required ucode modules
    opkg update
    opkg install ucode libucode ucode-mod-fs ucode-mod-ubus ucode-mod-uci ucode-mod-math ucode-mod-uclient ucode-mod-uloop ucode-mod-log liblucihttp-ucode

    # Install the package
    opkg install /tmp/luci-sso*.ipk
    ```

---

## ⚙️ Configuration

The configuration is located at `/etc/config/luci-sso`.

### 1. Identity Provider (IdP) Setup
Configure your OIDC provider. You will need a **Client ID** and **Client Secret**.
*   **Redirect URI:** `https://<YOUR_ROUTER_IP_OR_DOMAIN>/cgi-bin/luci-sso/callback`
*   **Note:** The router and IdP interactions **MUST** use HTTPS.

### 2. Router Configuration
Edit `/etc/config/luci-sso`:

```properties
config oidc 'default'
    # Must be set to '1' to activate the service
    option enabled '0'

    # The URL where the router will fetch .well-known/openid-configuration
    # MUST use https://
    option issuer_url 'https://auth.example.com/realms/homelab'
    
    # (Optional) If the router needs a different internal URL to reach the IdP
    # option internal_issuer_url 'http://10.0.0.5:8080/realms/homelab'

    option client_id 'luci-router'
    option client_secret 'YOUR_SECRET_HERE'
    
    # Must match exactly what is configured in your IdP
    # MUST use https://
    option redirect_uri 'https://192.168.1.1/cgi-bin/luci-sso/callback'
    
    # Standard scopes
    option scope 'openid profile email'

    # Allowed clock skew in seconds for JWT validation (REQUIRED)
    option clock_tolerance '300'

# Map OIDC Users or Groups to Roles
config role 'admin'
    # Match by OIDC email(s)
    list email 'admin@example.com'
    # Match by OIDC group(s)
    list group 'admins'
    
    # Granular ACL mapping (Use list for multiple groups)
    # Use '*' for full administrative access
    list read '*'
    list write '*'

config role 'parents'
    list email 'father@example.com'
    list email 'mother@example.com'
    list group 'family'
    list read 'luci-mod-status'
    list read 'luci-mod-network'
    list write 'luci-mod-network-config'
```

### 3. Apply Changes
Configuration changes take effect immediately for new login attempts. No service restart is required.

If you edited the file using `uci set` commands, remember to commit:
```bash
uci commit luci-sso
```

---

## 🛡️ Security & Compliance

This project has been hardened against modern OIDC attack vectors.

*   **OIDC Core 1.0 Compliance:** Enforces `iss`, `aud`, `exp`, `iat`, `nonce`, and `azp` validation.
*   **RFC 7636 (PKCE):** Mandatory S256 PKCE for all flows.
*   **Token Binding:** Enforces `at_hash` validation to prevent access token substitution.
*   **Anti-Replay:**
    *   Handshake states are one-time use (atomic filesystem locks).
    *   Access tokens are tracked for 24 hours to prevent replay attacks.
*   **DoS Protection:** HTTP response bodies are capped at 256KB to prevent memory exhaustion on embedded devices.
*   **Audit Logging:** All security events are logged to syslog (`logread`). PII is redacted where possible.

---

## ❓ Troubleshooting

**Logs:**
Check the system log for detailed authentication traces:
```bash
logread -e luci-sso
```

**Common Errors:**
*   `SYSTEM_INIT_FAILED`: The `/etc/luci-sso` directory permissions are wrong or the crypto backend failed to initialize.
*   `OIDC_DISCOVERY_FAILED`: The router cannot reach the `issuer_url`. Check DNS and Firewall settings.
*   `SSL_INIT_FAILED`: The router does not trust the IdP's SSL certificate. Install `ca-bundle` or add your CA to `/etc/ssl/certs`.

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
