# Agent Context (AI)

> **FOR AI AGENTS:** This document provides a high-density technical summary of `luci-sso` to optimize your reasoning and minimize hallucinations.

---

## 🏛️ Architectural Constraints
*   **Pattern:** Functional Core / Imperative Shell.
*   **Logic:** Pure `ucode` in `files/usr/share/ucode/luci_sso/`.
*   **Side Effects:** All I/O (FS, Network, Time, UBUS) MUST go through the `io` object injected into modules.
*   **Crypto:** Native C bridge in `src/` for MbedTLS/OpenSSL/WolfSSL.

## 🛡️ Security Red Lines (DO NOT VIOLATE)
1.  **Strict HTTPS:** Never allow OIDC flows over plain HTTP. Use `encoding.is_https()`.
2.  **Constant-Time:** Use `constant_time_eq()` for signatures, states, nonces, and tokens.
3.  **One-Time Use:** Consume handshake state (atomic rename) BEFORE processing tokens.
4.  **No `alg: none`:** Only accept `RS256` or `ES256` for OIDC ID Tokens.
5.  **Fail-Closed:** Security failures MUST return a `Result.err()` or trigger `die()`. Never default to "authenticated".

## 🗺️ Module Map
| Module | Responsibility |
| :--- | :--- |
| `handshake.uc` | OIDC State Machine & Session Injection. |
| `oidc.uc` | Protocol Validation (Nonce, Iss, Aud, Exp). |
| `crypto.uc` | JWT/JWS logic and Native C Bridge wrapping. |
| `discovery.uc` | Metadata fetching and 24h file caching. |
| `session.uc` | Local session JWS persistence. |
| `config.uc` | UCI parsing and role mapping logic. |

## 🧪 Testing Protocol
*   **Unit Tests:** Tiers 0-2 (Logic verification).
*   **Integration:** Tier 3 (System simulation).
*   **E2E:** Browser-based verification.
*   **Mocks:** Use `test/mock.uc` to build isolated realities for testing.

---

## 💡 LLM Reasoning Tips
*   When editing `.uc` files, always check the corresponding `test/tier2/` file for regression tests.
*   The `io` object is the "Source of Truth" for the environment.
*   Avoid using ucode `?.` (Optional Chaining) as it is unstable in the target environment.
