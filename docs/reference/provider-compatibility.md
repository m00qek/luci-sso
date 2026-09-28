# Provider Compatibility

The requirements `luci-sso` enforces on an identity provider (IdP), and the status of the providers this documentation covers. Error codes are described in [Log Messages](log-messages.md).

---

## Requirements

### Discovery

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| HTTPS issuer | `issuer_url` starts with `https://` | `CONFIG_ERROR` |
| Discovery document | `<issuer_url>/.well-known/openid-configuration` returns HTTP 200 with a JSON object | `[502] OIDC_DISCOVERY_FAILED` |
| Matching issuer | The document's `issuer` equals `issuer_url`. Scheme and host case, the default port and trailing slashes are ignored. | `DISCOVERY_ISSUER_MISMATCH: issuer_url is "…" but the discovery document declares "…"`, then `[502] OIDC_DISCOVERY_FAILED` |
| Endpoints | `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present and HTTPS | A `DISCOVERY_MISSING_ENDPOINT` or `INSECURE_ENDPOINT` line naming the field, then `[502] OIDC_DISCOVERY_FAILED` |
| Authorization endpoint | Contains no `#` fragment (RFC 6749 §3.1) | `[500] INVALID_AUTH_ENDPOINT` |
| Optional endpoints | `userinfo_endpoint` and `end_session_endpoint` are used only when HTTPS. A plain-HTTP value is ignored with a warning. | None |

### Authorization request and token exchange

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| Authorization code flow | The request sends `response_type=code` and the `scope` option (default `openid profile email`) | The IdP's own error page, or `IDP_ERROR` |
| PKCE `S256` | The request sends `code_challenge_method=S256`; the token request sends `code_verifier`. `plain` is never used. | The IdP's own error |
| `state` | The IdP returns the `state` it was sent, with a `code` | [Callback errors](log-messages.md#callback-errors) |
| `nonce` | Sent in the request; checked in the ID Token (below) | See `nonce` below |
| Confidential client | `client_secret` is mandatory. `client_id` and `client_secret` are sent in the token request body (`client_secret_post`). | `CONFIG_ERROR`; a rejected client gives `TOKEN_EXCHANGE_FAILED` |
| Token response | HTTP 200 with a JSON body | `TOKEN_EXCHANGE_FAILED`, `OIDC_INVALID_GRANT`, `TOKEN_RESPONSE_INVALID_JSON` |
| ID Token issued | The response contains `id_token` | `[401] ID_TOKEN_VERIFICATION_FAILED`, detail `MISSING_ID_TOKEN` |
| Access token issued | The response contains `access_token` | Detail `MISSING_ACCESS_TOKEN` |
| Fresh access token per login | An access token is accepted once; the replay registry keeps it for 24 hours | `[403] TOKEN_REPLAYED` |

### ID Token signature

| Requirement | Check | Failure (detail of `ID_TOKEN_VERIFICATION_FAILED`) |
| :--- | :--- | :--- |
| Algorithm | Header `alg` is `RS256` or `ES256`. `HS256`, `none` and every other value are rejected. | `UNSUPPORTED_ALGORITHM` |
| Key lookup | The JWKS contains the key named by the header `kid`, after at most one forced JWKS refresh. Without a `kid`, the first key is used. | `KEY_NOT_FOUND`, `NO_KEYS_AVAILABLE` |
| Key type | `kty` is `RSA`, or `EC` with `crv` `P-256` | `UNSUPPORTED_KTY`, `UNSUPPORTED_CURVE` |
| RSA key | Modulus of at least 2048 bits; public exponent exactly 65537 | `INVALID_SIGNATURE`, `PEM_CONVERSION_FAILED` |
| Token size | At most 16 KB | `TOKEN_TOO_LARGE` |

### ID Token claims

| Claim | Check | Failure (detail of `ID_TOKEN_VERIFICATION_FAILED`) |
| :--- | :--- | :--- |
| `iss` | Equals `issuer_url`, normalized as for discovery | `ISSUER_MISMATCH` |
| `aud` | Equals `client_id`, or is a non-empty array of strings that contains it | `AUDIENCE_MISMATCH`, `INVALID_AUDIENCE`, `MALFORMED_AUDIENCE` |
| `exp` | Present, an integer, and not in the past by more than `clock_tolerance` | `MISSING_EXP_CLAIM`, `INVALID_EXP_CLAIM`, `TOKEN_EXPIRED` |
| `iat` | Present, an integer, and not in the future by more than `clock_tolerance` | `MISSING_IAT_CLAIM`, `INVALID_IAT_CLAIM`, `TOKEN_ISSUED_IN_FUTURE` |
| `nbf` | Optional. When present, an integer not in the future by more than `clock_tolerance`. | `INVALID_NBF_CLAIM`, `TOKEN_NOT_YET_VALID` |
| `sub` | Present | `MISSING_SUB_CLAIM` |
| `nonce` | Present and equal to the nonce sent in the authorization request | `MISSING_NONCE`, `NONCE_MISMATCH` |
| `azp` | Required when `aud` has more than one value. When present, equals `client_id`. | `MISSING_AZP_CLAIM`, `AZP_MISMATCH` |
| `at_hash` | Optional. When present, equal to the Base64URL-encoded left half of the access token's SHA-256. | `AT_HASH_MISMATCH` |

### Identity for role mapping

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| `email` or `groups` | Roles match on the `email` claim (case-insensitive) or on values of the `groups` claim (case-sensitive). `groups` must be a JSON array; any other type is ignored. When the ID Token has no `email`, the UserInfo endpoint is asked for `email`, and for `name` and `groups` if the ID Token lacks them. | `[403] USER_NOT_AUTHORIZED` |
| `email_verified` | With `require_email_verified` on (the default), the email counts for role matching only if `email_verified` is `true` or the string `"true"`, taken from the same response as the email: the ID Token, or UserInfo when the email came from there. Otherwise the email is ignored for matching and groups still match. See [Verified email](#verified-email). | `Ignoring the unverified email of user [sub_id: …] for role matching …`, then `[403] USER_NOT_AUTHORIZED` if no group matches |
| UserInfo response | HTTP 200 with a plain JSON object, not a signed JWT. Its `sub` matches the ID Token's `sub`. | `[403] IDENTITY_MISMATCH` for a different `sub`. Other UserInfo failures are logged as warnings and the login continues with the ID Token's claims. |

### Logout

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| `end_session_endpoint` | Optional. When the discovery document has an HTTPS one, LuCI's **Log out** for an SSO session sends the browser there with `id_token_hint` and `post_logout_redirect_uri`. Without one, the browser goes to `/` and the IdP session stays. | None |
| `post_logout_redirect_uri` | The origin of `redirect_uri` followed by `/`, for example `https://router.example.com/`. The IdP must accept it; most require it to be registered on the client. | The IdP's own error page |

---

## Providers

| Provider | Status | Guide | Notes |
| :--- | :--- | :--- | :--- |
| Google | Supported | [How to Configure Google](../how-to/providers/google.md) | Google accepts only a redirect URI whose host is a public domain name. Its discovery document has no `end_session_endpoint`, so **Log out** does not end the Google session. |
| Authelia | Supported | [How to Configure Authelia](../how-to/providers/authelia.md) | The client sets `token_endpoint_auth_method: client_secret_post` (Authelia defaults to `client_secret_basic`). By default `email` and `groups` come only from UserInfo, which must be plain JSON (`userinfo_signed_response_alg: none`, the default); a `claims_policy` can put them in the ID Token. There is no `end_session_endpoint`, so **Log out** does not end the Authelia session. |
| Keycloak | Supported | [How to Configure Keycloak](../how-to/providers/keycloak.md) | **Client authentication** must be on, which makes the client confidential. Keycloak refuses `groups` in the scope with `invalid_scope` unless a client scope of that name exists; a Group Membership mapper on the client's dedicated scope sends the claim instead (checked with Keycloak 26.7.4). |
| Authentik | Supported | [How to Configure Authentik](../how-to/providers/authentik.md) | A **Signing Key** must be selected; new providers have one preselected. Without one, Authentik signs ID Tokens with `HS256` and the client secret ([Authentik docs](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)), which fails the login with `JWKS_FETCH_FAILED`, or with `UNSUPPORTED_ALGORITHM` while the router still has Authentik's earlier keys cached (up to 24 hours). Its ID Tokens have no `at_hash` in the authorization code flow, which `luci-sso` accepts. |
| Pocket ID | Supported | [How to Configure Pocket ID](../how-to/providers/pocket-id.md) | A new client allows no user until **Allowed User Groups** is set or unrestricted. Pocket ID creates no client secret until one is added on the **Credentials** tab. The `groups` claim holds each group's name as it is. |
| Other OIDC providers | Depends on the provider | [How to Configure a Generic OIDC Provider](../how-to/providers/generic-oidc.md) | Must meet every requirement above. |
| GitHub | **Not supported** | None | See [GitHub](#github). |

### Verified email

What each provider sends as `email_verified` for a user whose address an administrator entered, and what makes it `true`. Until it is `true`, an `email` rule does not match that user while `require_email_verified` is on; a `group` rule still does.

| Provider | ID Token | UserInfo | To send `true` |
| :--- | :--- | :--- | :--- |
| Google | `true` once Google has verified the address ([Google docs](https://developers.google.com/identity/openid-connect/openid-connect#an-id-tokens-payload)), as it has for Gmail and Workspace accounts | Same | Nothing to do. |
| Authelia 4.39.28 | Absent, unless the claims policy lists `email_verified` | `true` | Authelia sends `true` for every user, from the file or LDAP backend, without checking the address. With the `luci_sso` claims policy, list `email_verified` next to `email`; see [How to Configure Authelia](../how-to/providers/authelia.md#map-by-email). |
| Keycloak 26.7.4 | The user's **Email verified** setting, `false` by default for users an administrator creates | Same | Turn on **Email verified** on the user, or have Keycloak verify addresses by email; see [How to Configure Keycloak](../how-to/providers/keycloak.md#map-by-email). |
| Authentik 2026.8.3 | `false`, always, from the default `email` scope mapping (since 2025.10) | Same | Replace the default `email` scope mapping with one that returns `true`; see [How to Configure Authentik](../how-to/providers/authentik.md#map-by-email). |
| Pocket ID 2.16.0 | The user's verified flag, `false` by default | Same | Mark the user's email as verified, or turn on **Emails verified by default** for new addresses; see [How to Configure Pocket ID](../how-to/providers/pocket-id.md#map-by-email). |

Checked by signing in to Keycloak and Authelia, and in the Authentik and Pocket ID sources ([Authentik](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/#email-scope-verification), [Pocket ID](https://github.com/pocket-id/pocket-id/blob/v2.16.0/backend/internal/oidc/claims_service.go)). Earlier logins with Authentik and Pocket ID showed `false` in both places.

### GitHub

GitHub OAuth Apps and GitHub Apps do not issue ID Tokens. The token response GitHub documents for the web application flow contains `access_token`, `scope` and `token_type`, plus `refresh_token`, `expires_in` and `refresh_token_expires_in` when tokens expire ([GitHub docs](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)). A login that reaches the token exchange fails with `[401] ID_TOKEN_VERIFICATION_FAILED`, detail `MISSING_ID_TOKEN`.

| `issuer_url` | Result (checked September 2026) |
| :--- | :--- |
| `https://github.com` | The discovery request returns 404: `[502] OIDC_DISCOVERY_FAILED`. |
| `https://github.com/login/oauth` | A discovery document is served. Its `claims_supported` lists neither `email` nor `groups`, and it has no `userinfo_endpoint`. The token response still has no `id_token`. |

**Alternative:** [Dex](https://dexidp.io/docs/connectors/github/) signs users in through GitHub and issues its own OIDC tokens. When the `groups` scope is requested, Dex returns GitHub teams as `groups` values of the form `org:team`. Connect `luci-sso` to Dex with [How to Configure a Generic OIDC Provider](../how-to/providers/generic-oidc.md).
