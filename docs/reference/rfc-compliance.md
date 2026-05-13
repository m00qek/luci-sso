# RFC Compliance Matrix

This document maps the `luci-sso` implementation to the relevant OIDC and OAuth2 standards.

---

## 📜 Core Standards

| Standard | Scope | Implementation Status |
| :--- | :--- | :--- |
| **OIDC Core 1.0** | Authentication Flow | ✅ Fully Compliant. |
| **RFC 6749** | OAuth 2.0 Framework | ✅ Fully Compliant. |
| **RFC 7636** | PKCE (S256) | ✅ Mandatory. |
| **RFC 7519** | JSON Web Token (JWT) | ✅ Fully Compliant. |
| **RFC 7517** | JSON Web Key (JWK) | ✅ Fully Compliant. |

## 🛡️ Security Enforcement

| Requirement | Reference | Mechanism |
| :--- | :--- | :--- |
| **Nonce Validation** | OIDC §3.1.3.7 | Strict constant-time match in `oidc.uc`. |
| **State Validation** | RFC 6749 §4.1.1 | CSRF protection via atomic FS states. |
| **Algorithm Restriction** | Security Best Practices | Only `RS256` and `ES256` accepted. |
| **Token Binding** | OIDC §3.1.3.7 | `at_hash` validation enforced. |
| **Expiry Enforcement** | RFC 7519 §4.1.4 | `exp` and `iat` claims are mandatory. |

---

## 🔍 Audit Trail
Security auditors can verify these claims by inspecting the following modules:
*   **Protocol Logic:** `files/usr/share/ucode/luci_sso/oidc.uc`
*   **Crypto Primitives:** `files/usr/share/ucode/luci_sso/crypto.uc`
*   **Native Bridge:** `src/native_common.c`
