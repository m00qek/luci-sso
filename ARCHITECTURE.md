# LuCI SSO Architecture

This document describes the architectural design, security model, and key technical decisions of the `luci-sso` project.

---

## 1. Core Principles

### Functional Core / Imperative Shell
The project strictly follows the pattern of keeping business logic (OIDC, Session management) pure and testable, while isolating side effects (Network, FS, Time) into an "IO Provider" object.
*   **Functional Core:** ucode modules in `files/usr/share/ucode/luci_sso/`. Key components:
    *   `handshake.uc`: OIDC state machine and session bridging.
    *   `oidc.uc`: Pure OIDC protocol implementation.
    *   `discovery.uc`: Metadata fetching and caching.
    *   `crypto.uc`: Cryptographic primitives and JWT logic.
    *   `encoding.uc`: Pure data transformations.
*   **Imperative Shell:** The CGI script in `files/www/cgi-bin/luci-sso` which initializes the real `io` object and the `router.uc` CGI controller.
*   **IO Contract:** The `io` object MUST implement a standard set of methods: `time`, `random`, `read_file`, `write_file`, `rename`, `remove`, `mkdir`, `lsdir`, `stat`, `chmod`, `fserror`, `getenv`, `stdout`, `ubus_call`, `uci_cursor`, and **`log`**.
*   **Mandatory Auditing:** Logging is NOT optional. All security-relevant events, including handshake creation, validation failures, and network errors, MUST be logged for forensic purposes.
*   **Benefit:** Enables 100% offline unit testing without mocks for the logic itself.

### Minimal C Surface
C code is reserved exclusively for cryptographic primitives (`mbedtls` or `wolfssl`). 
*   **Why:** Reduces the security audit surface and simplifies cross-compilation. Logic stays in memory-safe ucode.

---

## 2. OIDC Networking: "Split-Horizon" Support

One of the most critical architectural decisions is the explicit support for environments where the **Browser** and the **Router** have different network paths to the Identity Provider (IdP).

---

## 3. Strict HTTPS Policy

To ensure transport security, the project enforces an exclusively HTTPS-based OIDC flow.

### Front-channel (Browser ↔ IdP)
*   **Enforcement:** The `issuer_url` MUST use the `https://` scheme.
*   **Reasoning:** Prevents leakage of Authorization Codes over insecure networks and ensures compatibility with `Secure` cookie flags.

### Back-channel (Router ↔ IdP)
*   **Enforcement:** All backend calls (Discovery, Token Exchange, JWKS) MUST be performed over HTTPS. Any configured `internal_issuer_url` must also use TLS.
*   **Verification:** The logic explicitly passes `verify: true` to the I/O provider. The router MUST reject any connection where the IdP's certificate is not trusted by the system's CA store.
*   **Token Binding:** The system enforces `at_hash` validation **unconditionally** for all flows (even where OIDC Core 1.0 makes it optional) to prevent token substitution attacks. Calculation MUST be performed using byte-safe extraction to prevent UTF-8 boundary errors.
*   **Replay Protection:** Handshake states are consumed using atomic POSIX `rename`. OIDC Access Tokens are registered in a local registry **immediately after exchange and BEFORE verification** (Fail-Safe consumption) to prevent brute-force signature or padding attacks.
*   **Algorithm Enforcement:** The system implements a **Two-Dimensional Config** (Security Policy). By default, it MUST ONLY accept asymmetric signatures (RS256, ES256). Symmetric algorithms (HS256) are strictly forbidden in production to prevent "Algorithm Confusion" attacks.
*   **Claims Validation:** Mandatory verification of `nonce` (Replay), `iss` (Issuer), `aud` (Audience), and `azp` (Authorized Party).
*   **Reasoning:** The back-channel carries sensitive credentials (`client_secret`, `access_token`). Insecure transport, weak binding, or reflective algorithm trust is never acceptable.

---

## 4. Environment Resilience

### Background Maintenance (Cron)
To prevent Algorithmic Complexity DoS attacks, periodic maintenance tasks (reaping expired tokens and handshakes) are decoupled from the CGI request loop.
*   **Orchestration:** A native OpenWrt cron job executes `/usr/sbin/luci-sso-cleanup` daily.
*   **Benefit:** Ensures the hot-path (Authentication) remains performant even under heavy load or abandoned flows.

---

## 5. Session & CSRF Handling

### Security Cookies
The system utilizes the `__Host-` cookie prefix for all session-related cookies.
*   **Requirement:** This mandates `Secure`, `Path=/`, and prevents cookie shadowing from subdomains, fulfilling modern web security best practices.

### Modern LuCI Hook (JavaScript)
Since LuCI 24.10 uses a dynamic client-side rendering model (pure JS), we do not use server-side Lua templates.
*   **Injection:** A small JS hook (`luci-sso-login.js`) is injected into the global LuCI header via a `uci-defaults` patch to `header.ut`.
*   **Lifecycle:** The hook uses a `MutationObserver` combined with a polling fallback to detect when the login modal is rendered and injects the "Login with SSO" button dynamically.
*   **Aesthetics:** The button is styled using LuCI's native CSS classes and a custom blue gradient to match the system "success" pattern.

---

## 6. UBUS Integration

### Logic & Session Injection
Upon a successful OIDC handshake, the service:
1.  Performs a standard `ubus session login` using a "template" system user (e.g., `root`).
2.  Generates a random **CSRF Token**.
3.  Injects the OIDC user's identity and the CSRF token into the session via `ubus session set`.
4.  Redirects the user to the LuCI dashboard.

### Modern CSRF Synchronization
By creating a valid UBUS session and setting the `sysauth` cookies, modern LuCI (JS) automatically fetches the CSRF token from the session state on the first authenticated request, closing the loop between the OIDC flow and LuCI's write protection.

---

## 7. Session Termination (Logout)

The system implements full session synchronization during logout to prevent "Local Logout" confusion.

### RP-Initiated Logout
*   **Enforcement:** When the user accesses `/logout`, the system MUST perform OIDC Discovery to locate the IdP's `end_session_endpoint`.
*   **Protocol:** If the endpoint is available, the User Agent MUST be redirected there with an `id_token_hint` (retrieved from the UBUS session) and a `post_logout_redirect_uri`.
*   **Cleanup:** The local UBUS session MUST be destroyed and session cookies (`sysauth`, `sysauth_https`) MUST be cleared BEFORE the redirect occurs.
*   **Reasoning:** This ensures that the user's session is terminated both on the router and at the Identity Provider, preventing subsequent silent logins.

---

## 8. Testing Tiers

| Tier | Scope | Goal |
| :--- | :--- | :--- |
| **Unit** | Individual `.uc` modules | Verify crypto and logic (Offline). |
| **Integration** | CGI script + `ubus` | Verify HTTP headers and system wiring. |
| **E2E** | Full Stack (Compose) | Verify the complete OIDC flow against a Mock IdP. |

---

## 9. Development Orchestration

### The "Builder-as-a-Service" Pattern
To avoid massive build times and environment drift, the project uses a dedicated `sdk` service within Docker Compose.
*   **Encapsulation:** All OpenWrt SDK logic (feeds, cross-compilation, packaging) is contained within the `sdk` container.
*   **Source of Truth:** The `devenv/Makefile` dynamically parses dependencies from the root `Makefile`, ensuring the dev environment always matches the production recipe.
*   **Incremental Builds:** A host-side sentinel (`bin/lib/.built`) tracks changes to `src/*.c`, triggering the SDK compiler only when native code is modified.

### Layered Environment
1.  **PKI Service:** Generates a local Dev CA and per-service TLS certificates (ECC P-256).
2.  **IdP Service:** A Node.js Mock Identity Provider for OIDC flow testing.
3.  **LuCI Service:** The target OpenWrt runtime, mounting local project files for "hot-reload" development.
4.  **Browser Service:** A Playwright-enabled container for automated E2E testing.
