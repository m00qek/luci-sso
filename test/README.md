# Luci-SSO Test Suite: The Platinum Standard

This directory contains the exhaustive test suite for `luci-sso`. The suite is designed using a **Tiered Testing Architecture** to ensure mathematical honesty, protocol compliance, and system-wide reliability.

---

## **The Philosophy: Why Tiered Testing?**

Cryptography and OIDC flows are fragile. A failure could be a simple logic bug (wrong timestamp check) or a catastrophic mathematical failure (buffer overflow in C). 

We use a tiered approach to:
1.  **Isolate Failure Domains:** Instantly know if a bug is in the C-backend, the ucode plumbing, or the OIDC business logic.
2.  **Ensure Mathematical Honesty:** Prove the C-backend matches OpenSSL results bit-for-bit.
3.  **Adversarial Defense:** Proactively test "Paranoid" scenarios like signature malleability, key confusion, and future-dated tokens.

### **Mandatory Isolation Rule**
**FIXTURE ISOLATION**: Each tier MUST define its own fixtures or use its own generation helpers. **CROSS-TIER FIXTURE IMPORTS ARE FORBIDDEN.** This ensures that a change in one tier's data requirements does not cause cascading failures in unrelated tiers.

---

## **The Tiers**

### **Tier 0: Backend Compliance (`unit/native_*`)**
*   **Goal:** Certification of the C extension (`native.so`).
*   **Method:** Direct mathematical verification of SHA256, HMAC, RSA, and ECDSA against **OpenSSL Golden Values**.
*   **Focus:** Memory safety, binary robustness (null-byte handling), and raw mathematical correctness.

### **Tier 1: Cryptographic Plumbing (`unit/crypto_plumbing_*`)**
*   **Goal:** Secure Gatekeeping.
*   **Method:** Verify the transformation logic (JWK-to-PEM) and structural JWT validation.
*   **Focus:** Rejecting malformed JSON, enforcing size limits, and ensuring fail-fast component decoding.

### **Tier 2: Business & Protocol Logic (`unit/*_logic_*`)**
*   **Goal:** 100% OIDC Compliance.
*   **Method:** Dynamic **HS256 token generation** using a local secret.
*   **Focus:** Expiration, nonces, audience/issuer matching, and whitelist authorization.

### **Tier 3: Behavioral Integration (`integration/router_test.uc`)**
*   **Goal:** System-wide Specification.
*   **Method:** High-level BDD-style (`when/and/then`) testing using a single verified **Anchor RS256 Token**.
*   **Focus:** UCI configuration loading, UBUS integration, and end-to-end handshake wiring.

---

## **Tier Differentiation Strategy**

| Tier | Prefix | Target | Data Source | Failure Domain |
| :--- | :--- | :--- | :--- | :--- |
| **0** | **COMPLIANCE:** | `native.so` | Raw Primitives | C-Level Math / Memory |
| **1** | **PLUMBING:** | `crypto.uc` | `tier1_fixtures.uc` | Format / Encoding / Hand-off |
| **2** | **LOGIC:** | `oidc.uc` | `helpers.uc` (Dynamic) | Protocol Rules / Claims |
| **3** | **ANCHOR:** | `router.uc` | `tier1_fixtures.uc` | Glue Code / UCI Config |

---

## **How to Run**

The primary entry point is the development Makefile:

```bash
# Run the entire suite against the default backend (mbedtls)
make -f dev.mk test

# Run with full diagnostic logs
make -f dev.mk test VERBOSE=1
```

---

## **Security Standards Met**
*   ✅ **Constant-Time Comparisons** for all secrets.
*   ✅ **Paranoid Encoding Enforcement** (Strict Base64URL).
*   ✅ **Malleability Defense** (Rejecting trailing garbage).
*   ✅ **Fail-Fast Structural Validation** before cryptographic operations.
*   ✅ **Hardware-Level Hardening** (Rejecting weak RSA exponents).