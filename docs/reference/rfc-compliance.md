# RFC Compliance Matrix

This document maps the `luci-sso` implementation to the relevant OIDC and OAuth2 standards. Each table lists the requirements of one part of the protocol, where the standard defines them, and whether `luci-sso` meets them. Security auditors can verify these claims by inspecting the modules listed in the [Audit trail](#audit-trail) section.

All project documents use RFC 2119 key words ("MUST", "SHOULD", "MAY", etc.) as defined in [RFC 2119](https://tools.ietf.org/html/rfc2119).

The **Status** column uses these values:

| Status | Meaning |
| :--- | :--- |
| ✅ Implemented / ✅ Accepted | `luci-sso` does what the standard specifies. |
| ❌ Not implemented / ❌ Not used / ❌ Rejected | `luci-sso` deliberately does not support it. |
| ⚠️ Intentional deviation / ⚠️ Stricter than required | `luci-sso` departs from the standard on purpose. See [Intentional deviations](#intentional-deviations). |

---

## Standards covered

The specifications this matrix refers to. The **Reference** columns below cite their sections.

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

The grant types, the parameters of the authorization and token requests, and the optional flow features.

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
| Refresh tokens | OIDC Core §12 | ❌ Not implemented | Stored but never used. See [notes](#authorization-code-flow-notes). |
| UserInfo endpoint (fallback) | OIDC Core §5.3 | ✅ Implemented | Fetched when `email` claim is absent from the ID Token. |
| UserInfo `sub` must match the ID Token `sub` | OIDC Core §5.3.2 | ✅ Implemented | Exact, case-sensitive string comparison. A UserInfo response whose `sub` is not exactly the ID Token's, including one whose `sub` is missing, not a string or empty, refuses the login with `[403] IDENTITY_MISMATCH`, and none of its claims are used. A failed UserInfo request (network error, HTTP error, invalid JSON) is not a `sub` problem: it is logged as a warning and the login continues with the ID Token's claims. |
| `email_verified` claim | OIDC Core §5.1 | ✅ Implemented | Only the JSON boolean `true` counts as verified, and only from the response that carried the email. See [UCI Configuration](uci-config.md#oidc-section-notes). |
| RP-Initiated Logout | [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) §2 | ✅ Implemented | See [notes](#authorization-code-flow-notes). |

### Authorization Code Flow notes

- **Refresh tokens.** A refresh token the IdP returns is stored in the `rpcd` session but never used. Sessions expire after LuCI's idle timeout (`luci.sauth.sessiontime`, one hour by default); re-authentication is required. By design — see [About the Session Lifecycle](../explanation/session-lifecycle.md).
- **RP-Initiated Logout.** `/cgi-bin/luci-sso/logout` redirects the browser to `end_session_endpoint`, if advertised over HTTPS, with `id_token_hint` and `post_logout_redirect_uri` (the origin of `redirect_uri`). LuCI's **Log out** entry sends SSO sessions there.

---

## OIDC Discovery (OIDC Discovery 1.0 §4)

How the router fetches and checks the IdP's discovery document. IdP (identity provider) is the OIDC service that signs users in and issues tokens.

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| Discovery document fetch from `<issuer>/.well-known/openid-configuration` | Discovery §4 | ✅ Implemented | Cached in `/var/run/luci-sso/` (tmpfs) for 24 hours; an expired copy is used while the IdP is unreachable. |
| `issuer` field validation | Discovery §4.3 | ✅ Implemented | Must be identical to `issuer_url`: an exact string comparison, so a trailing slash, letter case or an explicit default port counts as a difference. See [notes](#oidc-discovery-notes). |
| `authorization_endpoint` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| `token_endpoint` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| `jwks_uri` required | Discovery §3 | ✅ Implemented | Missing field triggers `DISCOVERY_MISSING_ENDPOINT`, logged with the field name. |
| All endpoints must use HTTPS | Discovery §4.2 | ✅ Implemented | See [notes](#oidc-discovery-notes). |
| `issuer` in discovery must match fetch URL | Discovery §4.3 | ⚠️ Intentional deviation | See [notes](#oidc-discovery-notes). |

### OIDC Discovery notes

- **`issuer` field validation.** A mismatch fails discovery: `DISCOVERY_ISSUER_MISMATCH: …`, naming both issuers, then `[502] OIDC_DISCOVERY_FAILED`. When the two differ only in a trailing slash, letter case in the scheme or host, or the default port, the line says so; a case difference in the path gets no hint. A cached discovery document is used only if its `issuer` is identical to `issuer_url` too.
- **HTTPS endpoints.** A non-HTTPS `authorization_endpoint`, `token_endpoint` or `jwks_uri` triggers `INSECURE_ENDPOINT`, logged with the field name and its (capped) URL. A non-HTTPS `userinfo_endpoint` or `end_session_endpoint` is dropped with a warning.
- **`issuer` and the fetch URL.** When `internal_issuer_url` is set (split-horizon), the discovery document is fetched from the internal address but `issuer` is validated against the public `issuer_url`. See [How to Configure Split-Horizon Networking](../how-to/sysadmin/split-horizon.md).

---

## ID Token Validation (OIDC Core §3.1.3.7 / RFC 7519)

The claims checked in every ID Token before a session is created. The error code for each failed check is in [Log Messages](log-messages.md#token-validation-errors).

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| `iss` claim validation | OIDC Core §3.1.3.7 (2) | ✅ Implemented | Must exactly match the discovery document's `issuer`, which is itself identical to `issuer_url`. A non-string `iss` fails. `ISSUER_MISMATCH`. |
| `aud` claim validation | OIDC Core §3.1.3.7 (3), RFC 7519 §4.1.3 | ✅ Implemented | Must be the string `client_id` or the one-entry array `[client_id]`. `AUDIENCE_MISMATCH` otherwise; an empty array is `INVALID_AUDIENCE` and a non-string entry anywhere in the array is `MALFORMED_AUDIENCE`. |
| Additional audiences not trusted by the Client | OIDC Core §3.1.3.7 (3) | ✅ Implemented | `luci-sso` trusts no audience but its own `client_id`, so an ID Token that lists any other audience is rejected with `AUDIENCE_MISMATCH`, whatever its `azp`. |
| `azp` claim validation | OIDC Core §2, §3.1.3.7 (5) | ✅ Implemented | Optional and never required. When the claim is present, whatever its value, it must be the string `client_id`: `""`, a number or `null` fails with `AZP_MISMATCH`. |
| `exp` claim validation | OIDC Core §3.1.3.7 (9) | ✅ Implemented | Clock skew tolerance applied via `clock_tolerance` UCI option. |
| `iat` claim validation | OIDC Core §3.1.3.7 (10) | ✅ Implemented | Required. Rejected only if it is in the future by more than `clock_tolerance`; there is no maximum age. |
| `sub` claim required | OIDC Core §2 | ✅ Implemented | Must be a non-empty string. A missing `sub`, `""`, a number or `null` triggers `MISSING_SUB_CLAIM`. For the UserInfo response's `sub`, see §5.3.2 above. |
| `nonce` claim validation | OIDC Core §3.1.3.7 (11) | ✅ Implemented | Constant-time comparison against stored nonce. |
| `at_hash` validation | OIDC Core §3.1.3.6, §3.1.3.8 | ✅ Implemented | Optional in the code flow (§3.1.3.6): an ID Token without `at_hash` is accepted. When present, it must equal the Base64URL-encoded left half of the access token's SHA-256, compared in constant time (`AT_HASH_MISMATCH`). |

---

## PKCE (RFC 7636)

Proof Key for Code Exchange binds the token request to the authorization request that started the login.

| Requirement | Reference | Status | Notes |
| :--- | :--- | :--- | :--- |
| Code verifier generation | RFC 7636 §4.1 | ✅ Implemented | 43 bytes from the CSPRNG, Base64URL-encoded to 58 characters. A stored verifier outside 43–128 characters is refused before the token request. |
| Code challenge method: `S256` | RFC 7636 §4.2 | ✅ Implemented | Every authorization request sends `code_challenge_method=S256`. |
| Code challenge method: `plain` | RFC 7636 §4.2 | ❌ Not used | Intentionally not supported — `plain` provides no security benefit over omitting PKCE entirely. |
| Code challenge sent with authorization request | RFC 7636 §4.3 | ✅ Implemented | |
| Code verifier sent with token request | RFC 7636 §4.5 | ✅ Implemented | |

---

## Algorithms (RFC 7518 / RFC 7519)

The ID Token signature algorithms and whether they are accepted.

| Algorithm | Status | Notes |
| :--- | :--- | :--- |
| RS256 (RSA + SHA-256) | ✅ Accepted | Minimum 2048-bit keys enforced in the native C bridge. |
| ES256 (ECDSA + P-256 + SHA-256) | ✅ Accepted | EC coordinate validation performed before use. |
| HS256 (HMAC-SHA-256) | ❌ Rejected | Intentionally blocked — symmetric algorithms are vulnerable to Algorithm Confusion attacks. See [Security Model](../explanation/security-model.md). |
| `alg: none` | ❌ Rejected | Unsigned tokens are never accepted. |

---

## Intentional deviations

Where `luci-sso` departs from a standard on purpose, what it does instead, and why.

| Deviation | Standard | What `luci-sso` does |
| :--- | :--- | :--- |
| Split-horizon issuer URL | OIDC Discovery §4.3 requires the fetch URL to match the issuer identifier. | When `internal_issuer_url` is set, back-channel requests use a different origin than `issuer_url`. |
| Refresh tokens not supported | OIDC Core §12 defines the Refresh Token flow. | Users re-authenticate when the session expires. |
| Implicit flow not supported | RFC 6749 §4.2 defines the Implicit Grant. | Supports only the authorization code flow. |
| `plain` PKCE method not used | RFC 7636 §4.2 defines both `plain` and `S256`. | Always uses `S256`. |

### Rationale

- **Split-horizon issuer URL.** Self-hosted deployments commonly cannot route the router's back-channel traffic through the IdP's public DNS name. Requiring a match would break most home lab configurations. The `iss` claim is still validated against the public `issuer_url`, preserving the security property that matters.
- **Refresh tokens not supported.** Sessions expire after LuCI's idle timeout and users re-authenticate on expiry, so the router never has to keep using long-lived credentials. The refresh token the IdP returns is stored in the in-memory `rpcd` session with the other tokens, but nothing reads it.
- **Implicit flow not supported.** The Implicit flow places tokens in redirect URLs, which are logged by browsers, proxies, and servers. It is deprecated by the OAuth 2.0 Security Best Current Practice (RFC 9700).
- **`plain` PKCE method not used.** `plain` sends the verifier as the challenge, providing no protection against an attacker who can observe the authorization request. `S256` is strictly superior when available.

---

## Audit trail

The source files that implement each area above. Verify the claims in this document by inspecting them:

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
