# Internal API Reference

This document provides a technical overview of the `luci-sso` internal modules for developers and AI agents.

---

## 🟢 ucode Modules (`luci_sso.*`)

### `handshake.uc`
Manages the OIDC state machine and UBUS session injection.
*   **Entry Point:** `handle_request(io, req)`
*   **Security:** Enforces atomic state consumption via POSIX `rename`.

### `oidc.uc`
Implements the core OpenID Connect protocol logic.
*   **Responsibility:** Validates ID Tokens, Nonces, and PKCE parameters.
*   **Standards:** RFC 6749, OIDC Core 1.0.

### `crypto.uc`
High-level API for cryptographic operations.
*   **Implementation:** Wraps the native C bridge (`native.so`).
*   **Features:** JWS signing/verification, JWT claim validation, constant-time comparisons.

---

## 🔵 Native C Bridge (`src/`)

The native bridge provides the performance and cryptographic primitives required for OIDC.

### Cryptographic Backends
*   **MbedTLS (Default):** Optimized for memory-constrained devices.
*   **OpenSSL:** Industry standard, used on high-end routers.
*   **WolfSSL:** Lightweight alternative with strong hardware acceleration support.

### Hardening Measures
*   **Buffer Limits:** Strict **16 KB** limit on all input parameters.
*   **Zeroization:** Sensitive material is zeroed from memory immediately after use.
*   **Coordinate Validation:** Explicit length checks for EC public keys (P-256) before parsing.

---

## 🧪 Testing API
See [Running Tests](../how-to/developer/testing.md) for details on using the `mock` and `testing` modules for development.
