# About the OIDC Login Flow

When a user clicks "Login with SSO", a sequence of cryptographic handshakes runs between the browser, the router, and the identity provider. Understanding this flow helps make sense of what `luci-sso` is doing when things go wrong — and why it is designed the way it is.

---

## The four phases

```mermaid
sequenceDiagram
    actor User
    participant B as Browser
    participant R as Router (luci-sso)
    participant I as Identity Provider

    User->>B: Click "Login with SSO"
    B->>R: GET /cgi-bin/luci-sso/

    Note over R: Phase 1 — Initiation
    R->>I: GET /.well-known/openid-configuration (cached 24 h) — back-channel
    R->>R: Generate state (CSRF), nonce (replay), PKCE pair
    R->>R: Save handshake to /var/run/luci-sso/handshake_{handle}.json
    R-->>B: 302 → IdP /authorize?state=…&nonce=…&code_challenge=…

    Note over B,I: Phase 2 — User authenticates at the IdP
    B->>I: Follow redirect
    I-->>B: Login page
    User->>B: Enter credentials
    B->>I: Submit
    I-->>B: 302 → Router /callback?code=…&state=…

    Note over R: Phase 3 — Code exchange & token validation
    B->>R: GET /callback?code=…&state=…
    R->>R: Check state (constant-time) and expiry, then consume handshake file (atomic)
    R->>I: POST /token (code + PKCE verifier) — back-channel
    I-->>R: {id_token, access_token}
    R->>I: GET jwks_uri (cached 24 h) — back-channel
    R->>R: Validate id_token: algorithm, signature, iss, aud, exp, nonce, at_hash
    opt Email claim missing from ID token
        R->>I: GET /userinfo — back-channel
        I-->>R: {email, groups, …}
    end

    Note over R: Phase 4 — Session injection
    R->>R: Register access_token (replay prevention)
    R->>R: Match claims to UCI roles
    R->>R: Inject UBUS session with ACLs
    R-->>B: 302 → /cgi-bin/luci/ (with session cookie)
    B->>User: LuCI dashboard
```

The textual summary below explains what happens in each phase.

**Phase 1 — Initiation:** The router loads the IdP's discovery document, generates the security parameters for this specific login attempt and redirects the browser to the IdP.

**Phase 2 — IdP authentication:** The browser handles everything. The router is not involved. The user enters their credentials and the IdP redirects back with a short-lived authorization code.

**Phase 3 — Code exchange:** The router's back-channel takes over. The code is exchanged for tokens, and every security property of the tokens is verified before anything is trusted.

**Phase 4 — Session injection:** The access token is registered so it cannot be used for a second login, the user's identity is mapped to a LuCI role, and a session is created. The browser receives a session cookie and lands on the dashboard.

---

## Why the flow is designed this way

### The authorization code, not the token, travels through the browser

The browser is an untrusted environment. Browser history, proxies, logged redirects, and injected scripts can all observe URL parameters. The OIDC authorization code flow keeps the actual tokens off the browser entirely — the code that travels through the browser is short-lived, single-use, and worthless without the PKCE verifier that only the router holds.

The alternative — the implicit flow, where the IdP puts the access token directly in the redirect URL — is deprecated precisely because tokens in URLs are dangerous.

### PKCE prevents authorization code injection

PKCE (Proof Key for Code Exchange) ties the authorization code to the specific device that initiated the flow. At initiation, the router generates a random `code_verifier` (kept secret on the router) and sends a `code_challenge` (SHA256 of the verifier) to the IdP. At code exchange, the router sends the verifier. The IdP verifies that SHA256(verifier) matches the challenge it stored.

An attacker who intercepts the authorization code cannot use it — they don't have the verifier. It never left the router.

### State prevents CSRF

The `state` parameter is a random value the router generates and sends to the IdP. When the IdP redirects back, the router checks the returned `state` matches what it generated — using constant-time comparison to prevent timing side-channels.

Without `state`, an attacker could craft a callback URL and trick the user's browser into completing an authentication flow the attacker initiated, potentially logging the user into the attacker's session.

### Nonce prevents token replay across sessions

The `nonce` is included in the authorization request and must appear verbatim in the ID Token the IdP issues. The router checks it at validation time using constant-time comparison.

This prevents an attacker from capturing a valid ID Token from one session and replaying it in another. The nonce is generated once and stored in the handshake file. That file is consumed at the callback, before the code is exchanged, so the nonce is checked exactly once and can never match again.

### The handshake file is atomically consumed

The handshake state file at `/var/run/luci-sso/handshake_{handle}.json` is first read and checked: the returned `state` must match and the handshake must not have expired. Only then is it claimed by atomically renaming it, before the code is exchanged. POSIX `rename` is guaranteed to either succeed or fail — two concurrent requests cannot both succeed on the same file. A request with the wrong `state` is rejected without touching the file, so a forged callback cannot cancel a login in progress.

This means each authorization code can only be processed once, even under concurrent requests. There is no time-of-check-time-of-use race condition.

### at_hash binds the access token to the ID token

The ID Token contains an `at_hash` claim: the base64url-encoded first 16 bytes of SHA256 of the access token. The router recomputes this and compares it using constant-time equality.

If an attacker substitutes a different access token in the token response — while somehow preserving a valid ID token — the `at_hash` check fails. The identity from the ID token cannot be decoupled from the access token actually received.

### Token registry prevents access token replay

After a successful login, the SHA256 hash of the access token is registered in `/var/run/luci-sso/tokens/`. This is an atomic `mkdir` operation: the first process to create the directory wins; subsequent attempts fail. A daily cleanup job removes entries older than 24 hours, and the router logs a warning when an access token lives longer than that window.

The registration happens only after the ID Token has been verified, so forged tokens cannot fill the registry. From then on, a token response carrying the same access token cannot create a second session: a replayed response, or an IdP that reissues access tokens, ends with `TOKEN_REPLAYED`.

---

## What can go wrong — and where

Each phase has distinct failure modes visible in the [system log](../reference/log-messages.md). A failed request ends with one `[<status>] <CODE>` line; the lines before it carry the detail:

| Phase | Code on the request's last line | Detail on the lines before it |
| :--- | :--- | :--- |
| Discovery | `OIDC_DISCOVERY_FAILED`, `JWKS_FETCH_FAILED` | `DISCOVERY_ISSUER_MISMATCH: …`, `DISCOVERY_MISSING_ENDPOINT: …`, `INSECURE_ENDPOINT: …`, `Discovery fetch failed … HTTP_REQUEST_FAILED (<cause>)`, `JWKS fetch HTTP <status> …` |
| Callback | `STATE_PARAMETER_MISMATCH`, `MISSING_HANDSHAKE_COOKIE`, `IDP_ERROR`, `STATE_NOT_FOUND` | `IDP_ERROR: the IdP returned error=<error> (…)`, `Callback state does not match the handshake; handshake kept`, `Handshake state not found or already consumed` |
| Token exchange | `TOKEN_EXCHANGE_FAILED`, `OIDC_INVALID_GRANT`, `TOKEN_ENDPOINT_NETWORK_ERROR` | `Token exchange HTTP <status>`, `Token exchange network error … (<cause>)` |
| Token validation | `ID_TOKEN_VERIFICATION_FAILED` | `OAuth flow failed …` naming the check, such as `UNSUPPORTED_ALGORITHM`, `NONCE_MISMATCH` or `AT_HASH_MISMATCH` |
| Authorization | `USER_NOT_AUTHORIZED` | `User [sub_id: …] matched no roles` |
| Session injection | `UBUS_LOGIN_FAILED` | `UBUS session creation failed` and similar |

For step-by-step troubleshooting, see [How to Debug luci-sso](../how-to/sysadmin/debugging.md).
