# About the Threat Model

A router's admin interface is a high-value target. Whoever controls LuCI controls the network: DNS, firewall rules, routing, VPN tunnels. `luci-sso` sits directly in front of that access, which means its failure modes are not abstract — a broken authentication implementation hands an attacker the network.

This document describes the landscape of threats that shaped the design, how each is addressed, and where residual risk remains. It pairs with the [Security Model](security-model.md), which explains the specific cryptographic mechanisms; and with [About the OIDC Login Flow](oidc-flow.md), which traces the sequence of events for each login.

---

## The attack surface

`luci-sso` operates at the boundary between three parties that do not fully trust each other:

- **The browser** is an untrusted environment. Browser history, extensions, local scripts, injected JavaScript, and logged HTTP requests can all observe anything that passes through a URL — including redirect parameters. The browser also runs code from arbitrary origins unless strict Content Security Policy headers prevent it.

- **The identity provider** is trusted to authenticate users correctly but is not trusted to issue arbitrary tokens that the router accepts without verification. A misconfigured, compromised, or rogue IdP should not be able to forge access to the router.

- **The network** between the router and the IdP is assumed to be untrusted. HTTPS is mandatory for all back-channel communication for exactly this reason — the router enforces it in code and refuses to proceed if any endpoint URL uses plain HTTP.

The router itself is the trusted party. All security-critical state (PKCE verifiers, nonces, handshake files, the token registry) lives only on the router.

---

## Authorization code injection

When a user clicks "Login with SSO", the router generates an authorization code challenge and redirects the browser to the IdP. The IdP authenticates the user and redirects back with a short-lived authorization code. An attacker who obtains that code — perhaps by observing a shared browser, logging redirect URLs, or using a CSRF-style trick to force another user's browser to submit the attacker's code — has a potential entry point.

PKCE closes this. The router generates a random `code_verifier`, keeps it on the router filesystem, and sends only a SHA256 hash of it (`code_challenge`) to the IdP. When the code is exchanged for tokens, the router must present the verifier — and only the router has it. An intercepted code is worthless without the verifier, which never left the router.

CSRF is separately prevented by the `state` parameter. The router generates a random state value, binds it to the browser session via a cookie, and checks the returned `state` at callback time using constant-time comparison. This ensures the callback request was initiated by the same browser that started the flow, not injected by a third party.

---

## Token replay

An attacker who captures a valid ID Token — from a logged network segment, a browser extension, or a compromised IdP response — might attempt to present it in a different session, perhaps after the legitimate user has logged out.

The `nonce` prevents this. The router generates a random nonce at flow initiation, embeds it in the authorization request, and the IdP must include it verbatim in the ID Token. The router verifies the nonce against the stored handshake state before accepting the token. Because the handshake file is deleted atomically at the moment of first use, the nonce can only be verified once — a replayed token with the same nonce finds no matching handshake to validate against.

After a successful login, the SHA256 hash of the access token is registered in the token registry (`/var/run/luci-sso/tokens/`). This is a distinct layer of protection: even if an attacker captures an access token that was already used for a valid login, attempting to reuse it will fail because the hash is already registered.

---

## Access token substitution

The token exchange is a back-channel request from the router to the IdP's token endpoint. An attacker with man-in-the-middle capability on that back-channel could, in theory, let the ID Token through unchanged while substituting a different access token.

The `at_hash` claim prevents this. The ID Token contains a binding to the access token: it includes the base64url-encoded first half of the SHA256 of the access token. The router recomputes this value from the actual access token it received and compares it using constant-time equality. If the access token has been substituted, the `at_hash` check fails and the login is rejected.

---

## Timing side-channels

Security-critical string comparisons — nonce verification, state verification, `at_hash` verification, logout CSRF token verification — all use a constant-time equality function. On an embedded device where cryptographic operations are measurable, a naive `==` comparison would leak information through timing: an attacker probing whether the first byte matches, then the second, could potentially reconstruct secret values by measuring response latency.

Constant-time comparison eliminates this by ensuring the comparison always takes the same amount of time regardless of how many bytes match. The implementation is in the native C bridge rather than ucode, both for performance and because compiler optimizations can inadvertently reintroduce timing variance in higher-level languages.

---

## Memory corruption in the C bridge

The native C bridge handles JWT parsing, JWK deserialization, RSA/EC signature verification, and PKCE computation. These are the operations that directly process attacker-controlled data — the contents of tokens issued by the IdP. A memory safety bug in this code could allow an attacker who controls the IdP to achieve arbitrary code execution on the router.

The bridge is hardened at multiple levels. All input is length-checked before any parsing begins — the 16 KB input limit in `web.uc` applies before data reaches the C layer, and the C code enforces its own bounds checks internally. EC public keys are validated (coordinate length, curve membership) before use. Memory containing sensitive material — private keys, raw token bytes, PKCE secrets — is zeroed immediately after use.

Coverage-guided fuzz testing exercises the parsing paths continuously. AddressSanitizer is enabled in CI to catch out-of-bounds reads and writes during test runs. The goal is not to eliminate all possible bugs — that is impossible to guarantee — but to make exploitation difficult and ensure that common classes of memory error are caught before they reach a release.

---

## Denial of service

An unauthenticated attacker can initiate login flows by sending requests to the `/` endpoint. Each request writes a handshake state file and makes a network connection to the IdP for discovery. Without a rate limit, this would allow an attacker to exhaust router memory, fill `/var/run/`, or overload the IdP with discovery requests.

The rate limiter allows 50 requests per 60-second window across all sources. This is a global limit, not per-source, which means a high-volume external attack will trigger it — but so will a legitimate user hammering the login button. The limit is set conservatively, since a human completing a login flow generates at most two or three requests (initiate, callback, logout).

The `?action=enabled` probe is exempt from rate limiting — it reads a single UCI value and produces no side effects, so it is safe to poll from monitoring scripts.

---

## What is out of scope

Some threats exist that `luci-sso` cannot address on its own:

**IdP compromise.** If the identity provider itself is compromised, an attacker who controls it can issue arbitrary tokens that pass all of `luci-sso`'s verification. The nonce, PKCE, and `at_hash` checks all assume the IdP is behaving correctly. Defence against a fully compromised IdP requires additional layers outside the scope of this project — for example, network segmentation that limits what a compromised router can reach.

**Physical access to the router.** An attacker with physical access to the router can read UCI configuration (including the client secret), mount the filesystem, or reset to factory defaults. luci-sso does not protect against physical access; that is an operational security concern.

**TLS failure.** All back-channel security assumes the router correctly verifies the IdP's TLS certificate. If the router's CA bundle is corrupted or if the TLS verification is bypassed (for example, by `curl -k` in a custom script), the guarantee that the router is talking to the real IdP is lost. luci-sso enforces HTTPS at the URL level; the underlying TLS library must be correctly configured.

**Session after logout.** UBUS sessions persist in router memory. If a user logs out but does not clear their browser cookies, the session cookie could be reused within its remaining lifetime. Logout triggers destruction of the UBUS session on the router, so the cookie becomes worthless as soon as the router processes the logout request — but only if the browser actually reaches `/logout`.
