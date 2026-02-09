# LuCI SSO Architecture

This document describes the architectural design, security model, and key technical decisions of the `luci-sso` project.

---

## 1. Core Principles

### Functional Core / Imperative Shell
The project strictly follows the pattern of keeping business logic (OIDC, Session management) pure and testable, while isolating side effects (Network, FS, Time) into an "IO Provider" object.
*   **Functional Core:** ucode modules in `files/usr/share/ucode/luci_sso/`.
*   **Imperative Shell:** The CGI script in `files/www/cgi-bin/luci-sso` which initializes the real `io` object.
*   **IO Contract:** The `io` object MUST implement a standard set of methods: `time`, `random`, `read_file`, `write_file`, `rename`, `remove`, `mkdir`, `lsdir`, `stat`, `http_get`, `http_post`, and **`log`**.
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

To achieve "Gold Standard" security, the project enforces an exclusively HTTPS-based OIDC flow.

### Front-channel (Browser ↔ IdP)
*   **Enforcement:** The `issuer_url` MUST use the `https://` scheme.
*   **Reasoning:** Prevents leakage of Authorization Codes over insecure networks and ensures compatibility with `Secure` cookie flags.

### Back-channel (Router ↔ IdP)
*   **Enforcement:** All backend calls (Discovery, Token Exchange, JWKS) MUST be performed over HTTPS. Any configured `internal_issuer_url` must also use TLS.
*   **Verification:** The logic explicitly passes `verify: true` to the I/O provider. The router MUST reject any connection where the IdP's certificate is not trusted by the system's CA store.
*   **Token Binding:** The system enforces `at_hash` validation for token binding if present in the ID Token (OIDC Core 3.1.3.3), preventing stripping attacks by requiring the Access Token if a hash is provided.
*   **Replay Protection:** Handshake states are consumed using atomic POSIX `rename` with a race-condition fallback to prevent token replay across concurrent requests.
*   **Claims Validation:** Mandatory verification of `nonce` (Replay), `iss` (Issuer), `aud` (Audience), and `azp` (Authorized Party).
*   **Reasoning:** The back-channel carries sensitive credentials (`client_secret`, `access_token`). Insecure transport or weak binding is never acceptable.

---

## 4. Environment Resilience

### HTTP Implementation: Native `uclient` with `uloop`
The project utilizes the native `uclient` ucode module integrated with the `uloop` event loop.
*   **Decision:** We implement a synchronous-looking wrapper in `https.uc` that leverages `uloop` to handle asynchronous HTTP events.
*   **Why:** This approach is more performant, provides better control over SSL context initialization, and eliminates the overhead of spawning shell processes. By using the OpenWrt SDK for builds, we ensure ABI compatibility for the native module across target architectures.

---

## 5. UI Integration Strategy

### Modern LuCI Hook (JavaScript)
Since LuCI 24.10 uses a dynamic client-side rendering model (pure JS), we do not use server-side Lua templates.
*   **Injection:** A small JS hook (`luci-sso-login.js`) is injected into the global LuCI header via a `uci-defaults` patch to `header.ut`.
*   **Lifecycle:** The hook uses a `MutationObserver` combined with a polling fallback to detect when the login modal is rendered and injects the "Login with SSO" button dynamically.
*   **Aesthetics:** The button is styled using LuCI's native CSS classes and a custom blue gradient to match the system "success" pattern.

---

## 6. Session & CSRF Handling

### UBUS Integration
Upon a successful OIDC handshake, the service:
1.  Performs a standard `ubus session login` using a "template" system user (e.g., `root`).
2.  Generates a random **CSRF Token**.
3.  Injects the OIDC user's identity and the CSRF token into the session via `ubus session set`.
4.  Redirects the user to the LuCI dashboard.

### Modern CSRF Synchronization
By creating a valid UBUS session and setting the `sysauth` cookies, modern LuCI (JS) automatically fetches the CSRF token from the session state on the first authenticated request, closing the loop between the OIDC flow and LuCI's write protection.

---

## 7. Testing Tiers

| Tier | Scope | Goal |
| :--- | :--- | :--- |
| **Unit** | Individual `.uc` modules | Verify crypto and logic (Offline). |
| **Integration** | CGI script + `ubus` | Verify HTTP headers and system wiring. |
| **E2E** | Full Stack (Compose) | Verify the complete OIDC flow against a Mock IdP. |

---

## 8. Development Orchestration

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
