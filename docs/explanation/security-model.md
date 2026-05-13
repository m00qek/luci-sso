# Security Model

`luci-sso` is designed with a "Security First" philosophy, specifically hardened against common OIDC and web-based attack vectors.

---

## 🛡️ Core Protections

### 1. OIDC & OAuth2 Compliance
We strictly follow **OIDC Core 1.0** and relevant RFCs:
*   **RFC 7636 (PKCE):** Mandatory S256 PKCE for all authorization flows to prevent authorization code injection.
*   **Token Binding:** Enforcement of `at_hash` validation to ensure access tokens haven't been substituted.
*   **Claim Validation:** Strict verification of `iss` (Issuer), `aud` (Audience), `exp` (Expiry), `iat` (Issued At), and `nonce` (Replay).

### 2. Anti-Replay Mechanisms
*   **Atomic State Consumption:** Handshake states are one-time use, enforced via atomic filesystem operations (POSIX `rename`).
*   **Token Registry:** Access tokens are tracked locally for 24 hours to prevent replay attacks using previously valid tokens.

### 3. Cryptographic Rigor
*   **Asymmetric Signatures:** We only accept RS256 or ES256 signatures for ID Tokens. Symmetric (HS256) is strictly forbidden for OIDC to prevent Algorithm Confusion attacks.
*   **Constant-Time Comparisons:** All sensitive comparisons (signatures, states, nonces) use constant-time logic to mitigate timing side-channel attacks.
*   **RSA Key Strength:** Minimum key size of 2048 bits enforced for all RSA operations.

### 4. Transport Security (Strict HTTPS)
*   **HTTPS Enforcement:** All OIDC interactions (Front-channel and Back-channel) MUST use HTTPS.
*   **SSL Verification:** The router rejects any connection to an IdP with an untrusted certificate.
*   **Security Headers:** Every HTTP response includes hardened headers:
    *   `Content-Security-Policy`: Prevents XSS.
    *   `X-Frame-Options: DENY`: Prevents Clickjacking.
    *   `Referrer-Policy: no-referrer`: Prevents leaking authorization codes.

---

## 🏗️ Virtual Identity Model
`luci-sso` implements a **Zero-Knowledge Credential Model**:
*   No local POSIX passwords are stored for OIDC users.
*   Identity is derived dynamically from OIDC claims mapped to UCI roles.
*   Access is granted via UBUS session injection with granular ACLs.
