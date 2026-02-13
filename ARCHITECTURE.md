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
    *   `session.uc`: Handshake and secret key persistence.
    *   `router.uc`: CGI request routing and logout orchestration.
    *   `config.uc`: UCI configuration parsing and validation.
    *   `web.uc`: HTTP request/cookie parsing.
    *   `secure_http.uc`: HTTPS scheme enforcement.
    *   `jwk.uc`: JWK to PEM conversion.
    *   `ubus.uc`: LuCI session and token registry via ubus.
    *   `io.uc`: I/O abstraction layer.
*   **Imperative Shell:** The CGI script in `files/www/cgi-bin/luci-sso` which initializes the real `io` object and the `router.uc` CGI controller.
*   **IO Contract:** The `io` object MUST implement a standard set of methods: `time`, `read_file`, `write_file`, `rename`, `remove`, `mkdir`, `lsdir`, `stat`, `chmod`, `fserror`, `getenv`, `stdout`, `ubus_call`, `uci_cursor`, `http_get`, `http_post`, `urlencode`, and **`log`**.
*   **Mandatory Auditing:** Logging is NOT optional. All security-relevant events, including handshake creation, validation failures, and network errors, MUST be logged for forensic purposes.
*   **Benefit:** Enables 100% offline unit testing without mocks for the logic itself.

### Minimal C Surface
C code is reserved exclusively for cryptographic primitives (`mbedtls` or `wolfssl`). 
*   **Why:** Reduces the security audit surface and simplifies cross-compilation. Logic stays in memory-safe ucode.
*   **Hardening:** To prevent buffer overflow and resource exhaustion attacks:
    *   The native bridge enforces a strict **16 KB** size limit on all input parameters (messages, signatures, keys).
    *   Public key parsing correctly distinguishes between PEM (requiring NUL termination) and DER (binary) formats to prevent out-of-bounds reads.
    *   HTTP response bodies are limited to **256 KB** at the ucode I/O layer to prevent memory exhaustion.
*   **Constant-Time Comparisons:** All sensitive comparisons (e.g., state, nonce, signatures, at_hash) MUST use `constant_time_eq`. This function is designed to avoid early returns on length or content mismatch to mitigate timing side-channels.

---

## 2. OIDC Networking: "Split-Horizon" Support

One of the most critical architectural decisions is the explicit support for environments where the **Browser** and the **Router** have different network paths to the Identity Provider (IdP).

### Metadata Caching Strategy
To reduce network overhead and ensure resilience against transient IdP outages, the system MUST implement a file-based caching strategy:
*   **Discovery Documents:** SHOULD be cached for **24 hours**.
*   **JWK Sets:** SHOULD be cached for **24 hours**.
*   **Atomic Updates:** All cache updates MUST use atomic POSIX `rename`.
*   **Resilience Fallback:** If a network fetch for discovery or JWKS fails, the system MUST attempt to load the existing (stale) cache as a fallback of last resort. This ensures device accessibility during upstream downtime.
*   **Forced Refresh:** The system MUST trigger a forced cache refresh if a cryptographic operation fails due to an unknown Key ID (`kid`).

### User-Agent vs. Router Networking (Split-Horizon)
In many deployments, the **Browser** accesses the IdP via a public URL (e.g., `https://auth.com`), while the **Router** MUST access it via an internal URL (e.g., `https://10.0.0.5`). 
*   **Logical vs. Physical:** The `issuer_url` serves as the logical OIDC identifier. The `internal_issuer_url` serves as the physical network fetch address.
*   **Origin Replacement:** When overriding IdP endpoints (token, jwks, userinfo) for the back-channel, the system MUST ONLY replace the **origin** (scheme + host + port) of the URL.
*   **Path Integrity:** Simple string replacement is strictly FORBIDDEN as it may corrupt path components if the issuer URL appears as a substring (e.g., in Keycloak realm paths).
*   **Security Bound:** The `issuer` claim in the discovery document and the `iss` claim in the ID Token MUST always match the logical `issuer_url`, regardless of the network path used to fetch them.
*   **Trigger:** If the mandatory `email` claim is missing from the verified ID Token, the system SHOULD attempt to fetch it from the `userinfo_endpoint`.
*   **Authentication:** The fetch MUST be performed using the `access_token` as a Bearer token over an encrypted (HTTPS) back-channel.
*   **Security Bound:** The `sub` claim returned by the UserInfo endpoint MUST match the `sub` claim from the cryptographically verified ID Token. Any mismatch MUST result in immediate session termination.

---

## 3. Strict HTTPS Policy

The system MUST enforce an exclusively HTTPS-based OIDC flow to ensure transport security.

### Front-channel (Browser ↔ IdP)
*   **Enforcement:** The `issuer_url` MUST use the `https://` scheme.
*   **Normalization:** All issuer URL comparisons MUST use normalized forms (lowercase scheme/host, no trailing slashes) to ensure interoperability across various IdP implementations.

### Back-channel (Router ↔ IdP)
*   **Enforcement:** All backend calls (Discovery, Token Exchange, JWKS) MUST be performed over HTTPS.
*   **Entropy Validation:** All cryptographic parameters (Secret Key, Nonce, State, CSRF tokens) MUST be sourced from a CSPRNG and explicitly validated for length and type. Any generation failure MUST result in a system halt (fail-closed) to prevent weak-key or CSRF vulnerabilities.
*   **Verification:** The router MUST reject any connection where the IdP's certificate is not trusted by the system's CA store.
*   **DoS Protection:** The system MUST enforce a **256 KB** maximum size limit on all incoming HTTP response bodies.
*   **Token Binding:** The system MUST enforce `at_hash` validation for all flows.
*   **Replay Protection:** Handshake states MUST be consumed using atomic POSIX `rename` for strict one-time use. OIDC Access Tokens MUST be registered in a local registry immediately AFTER successful cryptographic verification of the ID Token to prevent DoS attacks using unverified tokens.
*   **Algorithm Enforcement:** The system MUST ONLY accept asymmetric signatures (RS256, ES256) for OIDC ID Tokens. Symmetric algorithms (HS256) are strictly limited to internal session management via dedicated symmetric-only APIs. This separation prevents Algorithm Confusion attacks where a Public Key might be misused as an HMAC secret.
*   **Authorization Parameters:** Authorization URL generation MUST enforce the presence of `state` (min 16 chars), `nonce` (min 16 chars), and `code_challenge` (PKCE).
*   **Claims Validation:** The system MUST verify `exp` (Expiry), `iat` (Issued At), `nonce` (Replay), `iss` (Issuer), `aud` (Audience), and `azp` (Authorized Party). Both `exp` and `iat` MUST be present and valid to satisfy strict OIDC Core 1.0 §2 compliance and ensure robust token age validation.

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

## 6. UBUS Integration & Virtual Identity

The system implements a **Zero-Knowledge Credential Model**. The router does not store or require local POSIX passwords for OIDC-authenticated users.

### Virtual Identity Labeling
Upon a successful OIDC handshake, the system determines the user's identity based on matched UCI roles:
*   **Identity Mapping:** The `username` field in the LuCI session is set to the name of the first matched `config role` (e.g., `parents`, `admin`).
*   **Virtual Context:** This identity exists purely within the UBUS session state and does not require a corresponding account in `/etc/passwd`.

### Dynamic Grant Injection (Elevation)
Instead of inheriting permissions from a template user, the service programmatically constructs the session's authority:
1.  **Raw Creation:** Calls `session create` to obtain a fresh, unprivileged UBUS session ID (SID).
2.  **RBAC Mapping:** Maps OIDC claims (`email`, `groups`) to UCI roles. Multiple roles are merged using a logical OR.
3.  **Deduplicated Grants:** Calls `session grant` for each matched `access-group` defined in the roles.
4.  **Admin Wildcard Expansion:** If a role contains a wildcard (`*`), the system MUST:
    *   Grant full access to `ubus`, `uci`, `file`, and `cgi-io` scopes.
    *   Dynamically scan `/usr/share/rpcd/acl.d/` and grant ALL discovered `luci-*` access groups to ensure UI menu visibility.
5.  **Session Tagging:** Generates a random **256-bit CSRF Token** (CSPRNG validated) and injects OIDC metadata via `session set`.

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

### The "Builder-as-a-Service" Pattern (Authoritative SDK Model)
To avoid massive build times and environment drift, the project uses a dedicated `sdk` service within Docker Compose.
*   **Architecture Authority:** The environment MUST prioritize `SDK_ARCH` as the source of truth for builds. 
*   **Generic Target Strategy:** For the beta phase, the project utilizes "Generic" instruction sets (e.g., `aarch64_generic`) to ensure IPKs are portable across all boards within a CPU family.
*   **Encapsulation:** All OpenWrt SDK logic (feeds, cross-compilation, packaging) is contained within the `sdk` container.
*   **Source of Truth:** The `devenv/Makefile` dynamically parses dependencies from the root `Makefile`, ensuring the dev environment always matches the production recipe.
*   **Incremental Builds:** A host-side sentinel (`bin/lib/${SDK_ARCH}/.built-${CRYPTO_LIB}`) tracks changes to `src/*.c`, triggering the SDK compiler only when native code is modified.

### Layered Environment
1.  **PKI Service:** Generates a local Dev CA and per-service TLS certificates (ECC P-256).
2.  **IdP Service:** A Node.js Mock Identity Provider for OIDC flow testing.
3.  **LuCI Service:** The target OpenWrt runtime, mounting local project files for "hot-reload" development.
4.  **Browser Service:** A Playwright-enabled container for automated E2E testing.

---

## 10. Secret Key Management

The system uses a 256-bit symmetric key for signing local session tokens.
*   **Bootstrapping:** The key is generated automatically on first boot.
*   **Concurrency:** To prevent race conditions during the initial generation, the system utilizes a directory-based lock (`.lock`). 
*   **Resilience:** If a process finds the lock held by another, it implements a **retry loop with exponential backoff** to ensure it consumes the newly generated key rather than failing or falling back to a transient secret (which would invalidate subsequent session checks).
*   **Atomicity:** The key is written to a temporary file and moved into place using atomic `rename` to ensure filesystem consistency.
