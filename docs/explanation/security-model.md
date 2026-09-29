# About the Security Model

`luci-sso` treats security as a first-class constraint, not a layer applied after the fact. This shapes decisions at every level — which algorithms are allowed, how state is stored, what gets logged, how errors are handled. Understanding the reasoning behind these choices makes the code easier to audit and extend safely.

---

## The paranoid baseline

The starting assumption is that everything outside the router is potentially hostile: the IdP could be compromised, the network could be intercepted, the browser environment could be manipulated. This is not a theoretical concern — OIDC has a well-documented history of implementation vulnerabilities that come from trusting too much.

Consequently, `luci-sso` turns on every protection OIDC Core 1.0 and the associated RFCs offer to a client like it. PKCE is mandatory. Nonce validation is mandatory. The `iss`, `aud`, `exp`, and `iat` claims are always verified. `at_hash` is verified whenever the IdP sends it. This isn't excessive: each of these protections addresses a specific, documented attack. See the [Threat Model](threat-model.md) for the attack-by-attack breakdown.

The one place where the standard leaves the choice to the IdP is `at_hash`. In the authorization code flow, OIDC Core makes it optional, and some IdPs never send it. `luci-sso` accepts an ID Token without it, and refuses one whose `at_hash` does not match the access token. Refusing IdPs that follow the standard would lock their users out without closing a real gap, for the reasons given in [Access token substitution](threat-model.md#access-token-substitution).

---

## Why no HS256?

`luci-sso` only accepts RS256 and ES256 for ID Token signatures. Symmetric algorithms like HS256 are explicitly forbidden.

The reason is the Algorithm Confusion attack. In HS256, the signature key is a shared secret known to both the IdP and the verifier. If an attacker can convince the verifier to treat an RS256 public key as an HS256 secret, they can forge tokens using the public key — which is, by definition, public. The fix is to only accept asymmetric algorithms, where the signing key is private to the IdP and can never be confused with anything the verifier holds.

The allow-list is a constant in `oidc.uc`, not a UCI option or a function parameter, so that a misconfigured router cannot weaken it.

---

## Why constant-time comparisons?

Every comparison against a secret, or a value derived from one, uses the `constant_time_eq()` function rather than normal string equality: the `state`, the `nonce`, the `at_hash` and the logout CSRF token. Public identifiers — algorithm names, key IDs, issuers, audiences, role emails and groups — are compared with `===`, because their timing reveals nothing an attacker does not already know.

Standard equality operations return early when a mismatch is found, which means they take slightly less time for a near-correct guess than for a completely wrong one. Over thousands of requests, an attacker can measure these timing differences and gradually reconstruct a secret value.

`constant_time_eq()` (in `crypto/base.uc`) removes the early exit. It walks the full length of the longer input, folds every character difference into one value with XOR and OR, and only looks at the result at the end, so where the inputs differ no longer changes how long the loop runs. It is written in ucode, not C, and an interpreter cannot promise exact constant time: garbage collection, string handling and `ord()` all vary. The function's own comment says so. It is a best-effort mitigation that takes away the obvious signal, not a guarantee.

This is not a theoretical attack — timing side channels have been exploited in production OIDC implementations.

---

## Why atomic state consumption?

The OIDC handshake involves a `state` parameter that travels through the browser. When the browser returns from the IdP with an authorization code, the router must verify that the `state` matches one it generated — and then discard it, so it can never be used again.

`luci-sso` stores each handshake state as a file, written once by atomic rename and never modified. At the callback it first reads the file and checks it: the contents must be valid, the returned `state` must match (constant-time comparison), and the handshake must be within its time window. Only then does it claim the file by atomically renaming it to a consumed path. If two requests arrive with the right state simultaneously, only one can win the rename; the other sees a missing file and fails.

Checking before claiming matters because the handshake cookie is `SameSite=Lax`: a cross-site top-level link to `/callback` carries it. If the file were consumed first, such a link with a made-up `state` would destroy the victim's login in progress. With the check first, a wrong `state` is rejected with 403 and the handshake stays usable. A corrupt or expired handshake is removed, since it can never succeed.

The alternative — checking existence and then deleting in two steps — has a TOCTOU (time-of-check-time-of-use) race condition. Atomic rename eliminates it at the OS level.

---

## Zero-knowledge credential model

No local passwords are stored for OIDC users. For them there is nothing to steal, nothing to brute-force, and no credential database to protect. Identity is derived dynamically from OIDC claims on every login, mapped to a role, and expires with the session. The role's `rpcd` login entry holds its permissions but no password, so it cannot be used to log in.

This matters on a router, whose management interface is a common brute-force target. But SSO is an addition, not a replacement: LuCI's password form stays on the same login page, and the `root` account keeps its password. The password attack surface is unchanged, and protecting it — a strong password, and LuCI kept off the WAN — remains a separate task.

---

## Transport hardness

All OIDC interactions — both front-channel (browser redirects) and back-channel (router-to-IdP token exchange) — are required to use HTTPS. The `encoding.is_https()` utility is the single, centralized check for this; local `substr()` checks on URLs are explicitly prohibited because they're vulnerable to case-manipulation bypasses.

This extends to the LuCI session itself. Every cookie the module issues carries `Secure`, so a browser sends none of them over plain HTTP. luci-sso sets `sysauth_https` and the legacy `sysauth`, and never `sysauth_http`. A browser that reaches LuCI over `http://` therefore never presents the SSO session, and that setup is unsupported. What must be HTTPS is the browser's connection. `uhttpd` may serve plain HTTP to a reverse proxy that terminates TLS in front of it; see [How to Run LuCI Behind a Reverse Proxy](../how-to/sysadmin/reverse-proxy.md).

Certificate verification is always enabled. `ca-bundle` must be installed for the router to trust the IdP's certificate. Disabling certificate verification is not an option the configuration exposes.
