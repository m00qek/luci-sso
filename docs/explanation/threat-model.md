# Threat Model

This document analyzes the primary attack vectors against `luci-sso` and the implemented mitigations.

---

## 🎯 Threat Actors
1.  **External Attacker:** Unauthenticated user attempting to gain access to LuCI.
2.  **Malicious IdP:** A compromised or rogue Identity Provider attempting to inject malicious tokens.
3.  **Local User:** A user with low-level LuCI access attempting to escalate privileges.

---

## 🔍 Attack Vectors & Mitigations

### 1. Token Replay & Substitution
*   **Threat:** Attacker intercepts an ID Token and attempts to reuse it.
*   **Mitigation:** 
    *   **Nonce Validation:** Strict one-time use nonces verified in `oidc.uc`.
    *   **at_hash Binding:** Ensures the Access Token matches the ID Token.
    *   **Token Registry:** Access tokens are tracked for 24 hours to prevent reuse.

### 2. Authorization Code Injection (CSRF)
*   **Threat:** Attacker forces a user to complete an OIDC flow with the attacker's code.
*   **Mitigation:** 
    *   **PKCE (S256):** Mandatory Proof Key for Code Exchange.
    *   **Atomic State:** Handshake state is stored in an atomic file and deleted upon first read.

### 3. Timing Side-Channels
*   **Threat:** Attacker determines secrets by measuring the time taken for comparisons.
*   **Mitigation:** 
    *   **Constant-Time:** All sensitive checks (signatures, tokens, nonces) use `constant_time_eq()`.

### 4. Memory Corruption (Native C)
*   **Threat:** Malformed JWK or JWT causes a buffer overflow in the C crypto bridge.
*   **Mitigation:** 
    *   **Fuzz Testing:** Coverage-guided fuzzing of all native parsing logic.
    *   **ASan:** AddressSanitizer enabled during CI and development.
    *   **Strict Bounds:** 16KB input limits enforced in the C bridge.

---

## 🛡️ Trust Boundaries
*   **Router ↔ IdP:** Back-channel communication MUST be encrypted via TLS with certificate verification.
*   **Router ↔ Browser:** Communication MUST use HTTPS with HSTS and security headers.
