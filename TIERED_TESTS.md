# Tiered Testing Architecture

This document defines the strategy for achieving the "Gold Standard" of testing in `luci-sso` by separating cryptographic primitives, plumbing, protocol logic, and system integration.

---

## **Tier 0: Backend Compliance (The Primitive Tier)**

**Goal:** Ensure the C extension (`native.so`) adheres to the mathematical contract required by the project.

*   **Focus:** "Does the C library follow the laws of math?"
*   **Method:** Import the `luci_sso.native` module directly (bypassing the ucode wrappers).
*   **Target Modules:** `native_mbedtls.c`, `native_wolfssl.c`.
*   **Key Tests:**
    1.  **Bit-Level Primitives:** Compare SHA256 and HMAC-SHA256 results against known "golden" hex digests from OpenSSL.
    2.  **Raw Asymmetric Math:** Verify raw RS256 (RSA) and ES256 (ECDSA) signatures using raw PEM strings.
    3.  **Torture & Boundary Tests:** Verify that passing empty strings, binary garbage, or oversized buffers (e.g., 1MB) returns a clean `null/false` and **never crashes** the process.
    4.  **RNG Quality:** Ensure `random()` produces unique, high-entropy sequences.
*   **Rationale:** This suite acts as a "Certified Driver" test. It allows new crypto backends to be swapped in by proving they are a 100% mathematical match for the existing implementation.

---

## **Tier 1: Cryptographic Plumbing (Static / Asymmetric)**

**Goal:** Verify the `jwk_to_pem` conversion pipeline and ucode-to-C hand-off.

*   **Focus:** "Does the engine work?"
*   **Method:** Use fixed, mathematically verified RS256 and ES256 fixtures from `fixtures.uc`.
*   **Target Modules:** `crypto.uc`.
*   **Key Tests:**
    1.  **JWK Parsing:** Correctly extract `n`, `e`, `x`, `y` parameters from JSON.
    2.  **Strict Encoding:** Prove the system rejects `+` or `/` in JWK parameters (enforce strict Base64URL).
    3.  **Format Conversion:** Ensure the ucode layer produces exactly the PEM format the C-layer expects.
*   **Rationale:** Ensures the "heavy lifting" (RSA/EC math) is production-ready for real Identity Providers like Google or Keycloak.

---

## **Tier 2: Business & Protocol Logic (Dynamic / Symmetric)**

**Goal:** Exhaustively test every OIDC protocol rule and edge case.

*   **Focus:** "Does the router follow OIDC rules?"
*   **Method:** Use **HS256 (HMAC-SHA256)** to generate tokens on-demand using a symmetric secret.
*   **Target Modules:** `oidc.uc`, `session.uc`.
*   **Execution Scenarios:**
    1.  **Expiration/NBF:** Verify rejection of expired or future-dated tokens.
    2.  **Claims Validation:** Test `iss`, `aud`, and `sub` mismatch scenarios.
    3.  **Split-Horizon Logic:** Verify internal vs. external URL replacement.
    4.  **Nonce Tracking:** Verify state consistency across the handshake.
*   **Rationale:** Provides 100% logic coverage without the overhead of managing private RSA keys. Failure in this tier indicates a **Logic Bug**.

---

## **Tier 3: Integration & Wiring (The "Anchor" Test)**

**Goal:** Verify that all modules (Config, Router, Crypto, UBUS) are wired correctly.

*   **Focus:** "Is everything wired together?"
*   **Method:** One high-level "Happy Path" test using a real RS256 fixture.
*   **Target Modules:** `router.uc`, `cgi-bin/luci-sso`.
*   **Key Tests:**
    1.  **End-to-End Success:** Feed a valid RS256 token through the `/callback` route. Verify the response is a `302 Redirect` and that a UBUS session was created.
*   **Rationale:** Anchors the dynamic logic tests to real-world cryptographic primitives. Failure in this tier indicates a **Wiring/Config Bug**.

---

## **Tier Differentiation Strategy**

| Tier | Prefix | Target | Data Source | Failure Domain |
| :--- | :--- | :--- | :--- | :--- |
| **0** | **COMPLIANCE:** | `native.so` | Raw Primitives | C-Level Math / Memory |
| **1** | **PLUMBING:** | `crypto.uc` | `fixtures.uc` | Format / Encoding / Hand-off |
| **2** | **LOGIC:** | `oidc.uc` | `helpers.uc` | Protocol Rules / Claims |
| **3** | **ANCHOR:** | `router.uc` | Single Fixture | Glue Code / UCI Config |

### **Diagnostic Value**
1.  **`COMPLIANCE` Failure:** The C implementation is broken. Check memory management or math primitives.
2.  **`PLUMBING` Failure:** The ucode wrapper is broken. Check JWK parsing or Base64URL logic.
3.  **`LOGIC` Failure:** The business rules are wrong. Check OIDC claim validation or timestamp logic.
4.  **`ANCHOR` Failure:** The integration is broken. Logic and Crypto work, but they aren't talking correctly.