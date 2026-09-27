# RFC Compliance Matrix

All project documents use RFC 2119 key words ("MUST", "SHOULD", "MAY", etc.) as defined in [RFC 2119](https://tools.ietf.org/html/rfc2119).

This document maps the `luci-sso` implementation to the relevant OIDC and OAuth2 standards. Security auditors can verify these claims by inspecting the modules listed in the [Audit trail](#audit-trail) section.

---

## Standards covered

| Standard | Title |
| :--- | :--- |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | OpenID Connect Core |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | OpenID Connect Discovery |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | OAuth 2.0 Authorization Framework |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JSON Web Token (JWT) |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JSON Web Key (JWK) |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) | JSON Web Algorithms (JWA) |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | PKCE (Proof Key for Code Exchange) |
| [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | OpenID Connect RP-Initiated Logout |

---

## Authorization Code Flow (OIDC Core §3.1 / RFC 6749 §4.1)

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| Authorization Code Grant | RFC 6749 §4.1 | ✅ Implemented | Only supported grant type. |
| Implicit Grant | RFC 6749 §4.2 | ❌ Not implemented | Intentionally omitted — tokens in redirect URLs are deprecated as insecure. |
| Authorization request: `response_type=code` | OIDC Core §3.1.2.1 | ✅ Implemented | |
| Authorization request: `scope=openid` | OIDC Core §3.1.2.1 | ✅ Implemented | The default scope is `openid profile email`. The UCI `scope` option replaces the whole list, so a custom value must keep `openid`; add `groups` for group claims. |
| Authorization request: `state` parameter | RFC 6749 §4.1.1, §10.12 | ✅ Implemented | Random value, constant-time verified at callback. |
| Authorization request: `nonce` parameter | OIDC Core §3.1.2.1 | ✅ Implemented | Required. Constant-time verified against ID Token claim. |
| Token request: back-channel exchange | OIDC Core §3.1.3.1 | ✅ Implemented | HTTPS enforced. |
| Token response: `id_token` required | OIDC Core §3.1.3.3 | ✅ Implemented | Missing `id_token` triggers `MISSING_ID_TOKEN`. |
| Token error: `invalid_grant` handling | OIDC Core §3.1.3.4 | ✅ Implemented | Logged as `OIDC_INVALID_GRANT`. |
| Refresh tokens | OIDC Core §12 | ❌ Not implemented | A refresh token the IdP returns is stored in the `rpcd` session but never used. Sessions expire after LuCI's idle timeout (`luci.sauth.sessiontime`, one hour by default); re-authentication is required. By design — see [About the Session Lifecycle](../explanation/session-lifecycle.md). |
| UserInfo endpoint (fallback) | OIDC Core §5.3 | ✅ Implemented | Fetched when `email` claim is absent from the ID Token. |
| RP-Initiated Logout | [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) §2 | ✅ Implemented | `/cgi-bin/luci-sso/logout` redirects the browser to `end_session_endpoint`, if advertised over HTTPS, with `id_token_hint` and `post_logout_redirect_uri` (the origin of `redirect_uri`). LuCI's **Log out** entry sends SSO sessions there. |

---

## OIDC Discovery (OIDC Discovery 1.0 §4)

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| Discovery document fetch from `<issuer>/.well-known/openid-configuration` | Discovery §4 | ✅ Implemented | Cached in `/var/run/luci-sso/` (tmpfs) for 24 hours. |
| `issuer` field validation | Discovery §4.3 | ✅ Implemented | Must match `issuer_url` after normalization (host case, default port and trailing slashes ignored). A mismatch fails discovery: `DISCOVERY_ISSUER_MISMATCH: …`, naming both issuers, then `[500] OIDC_DISCOVERY_FAILED`. |
| `authorization_endpoint` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| `token_endpoint` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| `jwks_uri` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| All endpoints must use HTTPS | Discovery §4.2 | ✅ Implemented | A non-HTTPS `authorization_endpoint`, `token_endpoint` or `jwks_uri` triggers `INSECURE_ENDPOINT`, logged with the field name and its (capped) URL. A non-HTTPS `userinfo_endpoint` or `end_session_endpoint` is dropped with a warning. |
| `issuer` in discovery must match fetch URL | Discovery §4.3 | ⚠️ Intentional deviation | When `internal_issuer_url` is set (split-horizon), the discovery document is fetched from the internal address but `issuer` is validated against the public `issuer_url`. See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md). |

---

## ID Token Validation (OIDC Core §3.1.3.7 / RFC 7519)

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| `iss` claim validation | OIDC Core §3.1.3.7 (2) | ✅ Implemented | Must match `issuer_url` after URL normalization. |
| `aud` claim validation | OIDC Core §3.1.3.7 (3) | ✅ Implemented | Must include `client_id`. |
| `azp` claim validation | OIDC Core §3.1.3.7 (4), (5) | ✅ Implemented | Required when `aud` has several values; must equal `client_id` when present. |
| `exp` claim validation | OIDC Core §3.1.3.7 (9) | ✅ Implemented | Clock skew tolerance applied via `clock_tolerance` UCI option. |
| `iat` claim validation | OIDC Core §3.1.3.7 (10) | ✅ Implemented | Required. Rejected only if it is in the future by more than `clock_tolerance`; there is no maximum age. |
| `sub` claim required | OIDC Core §2 | ✅ Implemented | Missing `sub` triggers `MISSING_SUB_CLAIM`. |
| `nonce` claim validation | OIDC Core §3.1.3.7 (11) | ✅ Implemented | Constant-time comparison against stored nonce. |
| `at_hash` validation | OIDC Core §3.1.3.8 | ⚠️ Stricter than required | Always checked, and a missing `at_hash` is rejected (`MISSING_AT_HASH`), although §3.1.3.6 makes it optional in the code flow. See [Intentional deviations](#intentional-deviations). |

---

## PKCE (RFC 7636)

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| Code verifier generation | RFC 7636 §4.1 | ✅ Implemented | 43 bytes from the CSPRNG, Base64URL-encoded to 58 characters. A stored verifier outside 43–128 characters is refused before the token request. |
| Code challenge method: `S256` | RFC 7636 §4.2 | ✅ Implemented | Every authorization request sends `code_challenge_method=S256`. |
| Code challenge method: `plain` | RFC 7636 §4.2 | ❌ Not used | Intentionally not supported — `plain` provides no security benefit over omitting PKCE entirely. |
| Code challenge sent with authorization request | RFC 7636 §4.3 | ✅ Implemented | |
| Code verifier sent with token request | RFC 7636 §4.5 | ✅ Implemented | |

---

## Algorithms (RFC 7518 / RFC 7519)

| Algorithm | Status | Notes |
| :--- | :--- | :--- |
| RS256 (RSA + SHA-256) | ✅ Accepted | Minimum 2048-bit keys enforced in the native C bridge. |
| ES256 (ECDSA + P-256 + SHA-256) | ✅ Accepted | EC coordinate validation performed before use. |
| HS256 (HMAC-SHA-256) | ❌ Rejected | Intentionally blocked — symmetric algorithms are vulnerable to Algorithm Confusion attacks. See [Security Model](../explanation/security-model.md). |
| `alg: none` | ❌ Rejected | Unsigned tokens are never accepted. |

---

## Intentional deviations

| Deviation | Rationale |
| :--- | :--- |
| **Split-horizon issuer URL** — When `internal_issuer_url` is set, back-channel requests use a different origin than `issuer_url`. OIDC Discovery §4.3 requires the fetch URL to match the issuer identifier. | Self-hosted deployments commonly cannot route the router's back-channel traffic through the IdP's public DNS name. Requiring a match would break most home lab configurations. The `iss` claim is still validated against the public `issuer_url`, preserving the security property that matters. |
| **Refresh tokens not supported** — OIDC Core §12 defines the Refresh Token flow. | Sessions expire after LuCI's idle timeout and users re-authenticate on expiry, so the router never has to keep using long-lived credentials. The refresh token the IdP returns is stored in the in-memory `rpcd` session with the other tokens, but nothing reads it. |
| **`at_hash` required** — OIDC Core §3.1.3.6 makes `at_hash` optional in the authorization code flow. | `luci-sso` requires it so the access token it registers against replay is bound to the verified ID Token. IdPs that omit `at_hash` cannot be used. |
| **Implicit flow not supported** — RFC 6749 §4.2 defines the Implicit Grant. | The Implicit flow places tokens in redirect URLs, which are logged by browsers, proxies, and servers. It is deprecated by the OAuth 2.0 Security Best Current Practice (RFC 9700). |
| **`plain` PKCE method not used** — RFC 7636 §4.2 defines both `plain` and `S256`. | `plain` sends the verifier as the challenge, providing no protection against an attacker who can observe the authorization request. `S256` is strictly superior when available. |

---

## Audit trail

Verify the claims in this document by inspecting these source files:

| Area | Source |
| :--- | :--- |
| Authorization Code Flow orchestration, UserInfo fallback, token replay registration | `src/luci_sso/handshake.uc` |
| Authorization URL, token exchange, ID Token claims (nonce, `azp`, `at_hash`), algorithm allow-list | `src/luci_sso/oidc.uc` |
| JWT signature, `iss`, `aud`, `exp`, `nbf`, `iat` | `src/luci_sso/crypto/jwt.uc` |
| Discovery fetch, cache, issuer mismatch detection, JWKS | `src/luci_sso/discovery.uc` |
| PKCE generation (S256) | `src/luci_sso/crypto/pkce.uc` |
| Constant-time comparison | `src/luci_sso/crypto/base.uc` |
| `state` storage and verification | `src/luci_sso/session/handshake.uc` |
| JWK conversion | `src/luci_sso/crypto/jwk.uc`, `mod/native_api.c` (input guards), `mod/native_<lib>.c` (backends) |
| Signature verification | `mod/native_api.c` (input guards), `mod/native_<lib>.c` (backends) |
| RP-Initiated Logout | `src/luci_sso/router.uc` |
| HTTPS enforcement (`is_https()`) | `src/luci_sso/encoding.uc` |
