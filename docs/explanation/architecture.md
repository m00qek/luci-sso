# Architecture Design

This document describes the internal structure, module responsibilities, and key design patterns of `luci-sso`.

---

## 🏗️ Functional Core / Imperative Shell
The project strictly isolates business logic from side effects to ensure 100% testability.

### 1. Functional Core (ucode)
Located in `files/usr/share/ucode/luci_sso/`. These modules are pure logic and depend on an `io` provider for all external interactions.
*   **`handshake.uc`**: OIDC state machine and session bridging.
*   **`oidc.uc`**: Pure OIDC protocol implementation (Request/Response validation).
*   **`discovery.uc`**: Metadata fetching and 24h file-based caching.
*   **`crypto.uc`**: High-level crypto API (wraps the native C bridge).
*   **`config.uc`**: UCI configuration parsing and validation.

### 2. Imperative Shell (CGI)
Located in `files/www/cgi-bin/luci-sso`. This is the entry point that initializes the real `io` provider (Network, FS, Time) and hands it to the Functional Core.

---

## 🌐 Split-Horizon Networking
A critical feature for home labs where the **Browser** and **Router** see the Identity Provider at different addresses.

*   **`issuer_url`**: The logical OIDC identifier (used for `iss` claim validation).
*   **`internal_issuer_url`**: The physical network address used by the router for back-channel calls (Token exchange, JWKS fetch).

The system replaces only the **origin** of the IdP endpoints, preserving the paths to ensure compatibility with providers like Keycloak.

---

## ⚡ Native C Bridge
C code is reserved exclusively for performance-critical or security-sensitive cryptographic primitives.
*   **Backends:** Supports `mbedtls` (default), `wolfssl`, or `openssl`.
*   **Hardening:** Enforces strict buffer limits (16KB) and coordinate validation to prevent memory safety issues common in C.

---

## 🔄 Session Integration
`luci-sso` does not use local accounts. It injects "Virtual Identities" directly into the LuCI session state via UBUS:
1.  **Grant Injection:** Programmatically grants ACLs based on matched OIDC groups.
2.  **Wildcard Support:** Admin roles can dynamically scan and grant all discovered `luci-*` access groups.
3.  **CSRF Sync:** Injects a 256-bit CSRF token into the session to satisfy LuCI's write protection.
