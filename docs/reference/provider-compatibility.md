# Provider Compatibility

The requirements `luci-sso` enforces on an identity provider (IdP), and the status of the providers this documentation covers. Error codes are described in [Log Messages](log-messages.md).

---

## Requirements

### Discovery

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| HTTPS issuer | `issuer_url` starts with `https://` | `CONFIG_ERROR` |
| Discovery document | `<issuer_url>/.well-known/openid-configuration` returns HTTP 200 with a JSON object | `[500] OIDC_DISCOVERY_FAILED` |
| Matching issuer | The document's `issuer` equals `issuer_url`. Scheme and host case, the default port and trailing slashes are ignored. | `[500] OIDC_DISCOVERY_FAILED` |
| Endpoints | `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present and HTTPS | `[500] OIDC_DISCOVERY_FAILED` |
| Authorization endpoint | Contains no `#` fragment (RFC 6749 §3.1) | `INVALID_AUTH_ENDPOINT` |
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
| `aud` | Equals `client_id`, or is a non-empty array that contains it | `AUDIENCE_MISMATCH`, `INVALID_AUDIENCE` |
| `exp` | Present, an integer, and not in the past by more than `clock_tolerance` | `MISSING_EXP_CLAIM`, `INVALID_EXP_CLAIM`, `TOKEN_EXPIRED` |
| `iat` | Present, an integer, and not in the future by more than `clock_tolerance` | `MISSING_IAT_CLAIM`, `INVALID_IAT_CLAIM`, `TOKEN_ISSUED_IN_FUTURE` |
| `nbf` | Optional. When present, an integer not in the future by more than `clock_tolerance`. | `INVALID_NBF_CLAIM`, `TOKEN_NOT_YET_VALID` |
| `sub` | Present | `MISSING_SUB_CLAIM` |
| `nonce` | Present and equal to the nonce sent in the authorization request | `MISSING_NONCE`, `NONCE_MISMATCH` |
| `azp` | Required when `aud` has more than one value. When present, equals `client_id`. | `MISSING_AZP_CLAIM`, `AZP_MISMATCH` |
| `at_hash` | Present and equal to the Base64URL-encoded left half of the access token's SHA-256. OIDC Core makes it optional in the code flow; `luci-sso` requires it. | `MISSING_AT_HASH`, `AT_HASH_MISMATCH` |

### Identity for role mapping

| Requirement | Check | Failure |
| :--- | :--- | :--- |
| `email` or `groups` | Roles match on the `email` claim or on values of the `groups` array. When the ID Token has no `email`, the UserInfo endpoint is asked for `email`, and for `name` and `groups` if the ID Token lacks them. | `[403] USER_NOT_AUTHORIZED` |
| UserInfo response | HTTP 200 with a plain JSON object, not a signed JWT. Its `sub` matches the ID Token's `sub`. | `[403] IDENTITY_MISMATCH` for a different `sub`. Other UserInfo failures are logged as warnings and the login continues with the ID Token's claims. |

---

## Providers

| Provider | Status | Guide | Notes |
| :--- | :--- | :--- | :--- |
| Google | Supported | [How to Configure Google](../how-to/providers/google.md) | Google accepts only a redirect URI whose host is a public domain name. |
| Authelia | Supported | [How to Configure Authelia](../how-to/providers/authelia.md) | The client sets `userinfo_signed_response_alg: none`, so UserInfo returns plain JSON. |
| Keycloak | Supported | [How to Configure Keycloak](../how-to/providers/keycloak.md) | **Client authentication** must be on, which makes the client confidential. |
| Authentik | Supported | [How to Configure Authentik](../how-to/providers/authentik.md) | A **Signing Key** must be selected. Without one, Authentik signs ID Tokens with `HS256` and the client secret ([Authentik docs](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)), which fails with `UNSUPPORTED_ALGORITHM`. |
| Pocket ID | Supported | [How to Configure Pocket ID](../how-to/providers/pocket-id.md) | Group names carry the `@PocketID` suffix. |
| Other OIDC providers | Depends on the provider | [How to Configure a Generic OIDC Provider](../how-to/providers/generic-oidc.md) | Must meet every requirement above. Check a decoded ID Token for `at_hash`. |
| GitHub | **Not supported** | None | See [GitHub](#github). |

### GitHub

GitHub OAuth Apps and GitHub Apps do not issue ID Tokens. The token response GitHub documents for the web application flow contains `access_token`, `scope` and `token_type`, plus `refresh_token`, `expires_in` and `refresh_token_expires_in` when tokens expire ([GitHub docs](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)). A login that reaches the token exchange fails with `[401] ID_TOKEN_VERIFICATION_FAILED`, detail `MISSING_ID_TOKEN`.

| `issuer_url` | Result (checked September 2026) |
| :--- | :--- |
| `https://github.com` | The discovery request returns 404: `[500] OIDC_DISCOVERY_FAILED`. |
| `https://github.com/login/oauth` | A discovery document is served. Its `claims_supported` lists neither `email` nor `groups`, and it has no `userinfo_endpoint`. The token response still has no `id_token`. |

**Alternative:** [Dex](https://dexidp.io/docs/connectors/github/) signs users in through GitHub and issues its own OIDC tokens. When the `groups` scope is requested, Dex returns GitHub teams as `groups` values of the form `org:team`. Connect `luci-sso` to Dex with [How to Configure a Generic OIDC Provider](../how-to/providers/generic-oidc.md), and check that Dex's ID Tokens include `at_hash`.
