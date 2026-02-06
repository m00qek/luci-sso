# LuCI SSO Architecture

This document describes the architectural design, security model, and key technical decisions of the `luci-sso` project.

---

## 1. Core Principles

### Functional Core / Imperative Shell
The project strictly follows the pattern of keeping business logic (OIDC, Session management) pure and testable, while isolating side effects (Network, FS, Time) into an "IO Provider" object.
*   **Functional Core:** ucode modules in `files/usr/share/ucode/luci_sso/`.
*   **Imperative Shell:** The CGI script in `files/www/cgi-bin/luci-sso` which initializes the real `io` object.
*   **Benefit:** Enables 100% offline unit testing without mocks for the logic itself.

### Minimal C Surface
C code is reserved exclusively for cryptographic primitives (`mbedtls` or `wolfssl`). 
*   **Why:** Reduces the security audit surface and simplifies cross-compilation. Logic stays in memory-safe ucode.

---

## 2. OIDC Networking: "Split-Horizon" Support

One of the most critical architectural decisions is the explicit support for environments where the **Browser** and the **Router** have different network paths to the Identity Provider (IdP).

---

## 3. Strict HTTPS Policy

To achieve "Gold Standard" security, the project enforces an exclusively HTTPS-based OIDC flow.

### Front-channel (Browser ↔ IdP)
*   **Enforcement:** The `issuer_url` must use the `https://` scheme (exception granted for `localhost`).
*   **Reasoning:** Prevents leakage of Authorization Codes over insecure networks and ensures compatibility with `Secure` cookie flags.

### Back-channel (Router ↔ IdP)
*   **Enforcement:** All backend calls (Discovery, Token Exchange, JWKS) must be performed over HTTPS with strict certificate verification.
*   **Transport Exception:** The `internal_issuer_url` may use `http://` only if explicitly configured for trusted internal-only transport (e.g., Docker bridge), but the logical identity remains HTTPS.
*   **Trust Model:** The router will reject any connection where the IdP's certificate is not trusted by the system's CA store. This prevents Man-in-the-Middle (MitM) attacks during secret exchange.

---

## 4. UI Integration Strategy

### Modern LuCI Hook (JavaScript)
Since LuCI 24.10 uses a dynamic client-side rendering model (pure JS), we do not use server-side Lua templates.
*   **Injection:** A small JS hook (`luci-sso-login.js`) is injected into the global LuCI header via a `uci-defaults` patch to `header.ut`.
*   **Lifecycle:** The hook uses a `MutationObserver` combined with a polling fallback to detect when the login modal is rendered and injects the "Login with SSO" button dynamically.
*   **Aesthetics:** The button is styled using LuCI's native CSS classes and a custom blue gradient to match the system "success" pattern.

---

## 4. Environment Resilience

### HTTP Implementation: The `uclient-fetch` Wrapper
Due to ABI and library mismatch issues in some OpenWrt rootfs environments (specifically within Docker), the native `uclient` ucode module can be unstable.
*   **Decision:** The CGI entry point uses a robust wrapper around the `uclient-fetch` binary.
*   **Why:** Standalone binaries are immune to the symbol-relocation errors that often plague ucode plugins in development environments. This ensures the SSO service remains functional across a wider range of OpenWrt snapshots.

---

## 5. Session & CSRF Handling

### UBUS Integration
Upon a successful OIDC handshake, the service:
1.  Performs a standard `ubus session login` using a "template" system user (e.g., `root`).
2.  Generates a random **CSRF Token**.
3.  Injects the OIDC user's identity and the CSRF token into the session via `ubus session set`.
4.  Redirects the user to the LuCI dashboard.

### Modern CSRF Synchronization
By creating a valid UBUS session and setting the `sysauth` cookies, modern LuCI (JS) automatically fetches the CSRF token from the session state on the first authenticated request, closing the loop between the OIDC flow and LuCI's write protection.

---

## 6. Testing Tiers

| Tier | Scope | Goal |
| :--- | :--- | :--- |
| **Unit** | Individual `.uc` modules | Verify crypto and logic (Offline). |
| **Integration** | CGI script + `ubus` | Verify HTTP headers and system wiring. |
| **E2E** | Full Stack (Compose) | Verify the complete OIDC flow against a Mock IdP. |
