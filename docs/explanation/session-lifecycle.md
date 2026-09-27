# About the Session Lifecycle

After a successful login, `luci-sso` creates a LuCI session and hands the browser a session cookie. Understanding what that session is, how long it lasts, and when it ends matters for anyone reasoning about access control on the router.

```mermaid
stateDiagram-v2
    [*] --> Active : successful OIDC login\n(UBUS session created)
    Active --> Expired : idle timeout\n(luci.sauth.sessiontime)
    Active --> Terminated : logout, or destroyed by an admin\n(UBUS session destroyed)
    Expired --> [*]
    Terminated --> [*]
```

**Textual summary:** A session begins when the OIDC flow completes and UBUS creates the session record. From that point it either expires after LuCI's idle timeout (one hour by default, regardless of IdP token expiry) or is terminated immediately by a logout or by an administrator destroying it. Mid-session IdP revocation has no effect — the session continues until one of these two endpoints is reached. Multiple independent sessions can be active simultaneously.

---

## What a session is

`luci-sso` does not create local user accounts. There is no entry in `/etc/passwd`, no stored password, no local identity record. Instead, after a successful OIDC flow, it calls UBUS to create a **UBUS session** — an in-memory record managed by `rpcd` — and injects the user's ACLs and a CSRF token into it.

The browser receives a `sysauth_https` cookie containing the UBUS session ID. Every subsequent LuCI request presents this cookie; `rpcd` looks up the session and enforces the ACLs. From LuCI's perspective, a OIDC-authenticated user is indistinguishable from a password-authenticated one.

---

## Why the session lifetime follows LuCI, not the IdP

The session is created with LuCI's own session timeout, `luci.sauth.sessiontime` in `/etc/config/luci`: the same value LuCI passes to `rpcd` for a password login, so SSO and password sessions behave alike. OpenWrt ships it as `3600`; if the option is missing or not a positive integer, `luci-sso` uses 3600.

This is an **idle** timeout, not a hard cap. `rpcd` resets it every time the session is used, so an active user stays logged in and a session expires only after that many seconds without any LuCI request. To change it:

```bash
uci set luci.sauth.sessiontime='1800'
uci commit luci
```

The new value applies to sessions created after the change.

The IdP's ID Token carries its own `exp` claim, which `luci-sso` validates at login time — an expired token is rejected before a session is created. But once the session exists, `luci-sso` does not re-read the token's `exp` on subsequent requests. A token with a 5-minute expiry does not shorten the session to 5 minutes, and a token with a 24-hour expiry does not change it either.

The reason for decoupling session length from token expiry is the architectural constraint of the CGI model. `luci-sso` runs as a CGI script, not a daemon. There is no background process watching for token expiry and terminating sessions, and LuCI does not call `luci-sso` on later page loads, so nothing could re-check the tokens there. Doing so would also mean a back-channel call to the IdP on every request, which is expensive for an embedded router and introduces a new failure mode if the IdP is temporarily unreachable. Reusing LuCI's idle timeout keeps SSO sessions as long-lived as password sessions, without that cost.

The tokens themselves are kept. The access, refresh and ID tokens from the login are stored in the `rpcd` session, next to the user's email, for as long as the session lives. `luci-sso` only ever reads the ID token back, as the `id_token_hint` of an RP-Initiated Logout; it never refreshes or re-validates the others.

---

## What happens if the IdP revokes access mid-session

Nothing, immediately. `luci-sso` validates OIDC claims once, at login. If the IdP revokes a user's account or removes them from a group after they have logged in, the active LuCI session is not affected. The user retains their access until the session expires or they log out.

This is a known, documented residual risk. The mitigation available to administrators is to end the user's sessions on the router, which takes effect immediately: each SSO session is labelled with the user's email, so it can be found and destroyed without touching anyone else's. [How to Configure Role-Based Access Control](../how-to/sysadmin/rbac.md#end-a-users-sessions-now) shows the commands. The idle timeout also bounds the exposure window, but only once the session stops being used: an attacker who keeps using a stolen session keeps it alive.

---

## Logout mechanics

When a browser is sent to `/cgi-bin/luci-sso/logout`:

1. The CSRF token is verified — the request must include the `stoken` parameter matching the session's CSRF token.
2. The UBUS session is destroyed. The `sysauth_https` and `sysauth` cookies are cleared with `Max-Age=0`.
3. If the IdP's discovery document advertises an `end_session_endpoint`, the browser is redirected there, as defined by [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). Otherwise the browser is sent to `/`.

Destroying the UBUS session is immediate and complete — the session ID in the cookie becomes invalid the moment `rpcd` processes the destroy call. A browser holding a stale cookie after logout will be rejected on the next LuCI request.

The `end_session_endpoint` redirect is best-effort: if the IdP does not support it, the user is logged out of the router but remains authenticated at the IdP. A subsequent "Login with SSO" click will complete immediately without prompting for credentials again.

LuCI's own **Log out** link does not reach this endpoint. It goes through LuCI's dispatcher, which ends the router session but skips RP-Initiated Logout, so the user stays signed in at the IdP with the same effect as above. `luci-sso` does not currently rewrite that link.

---

## Session storage

UBUS sessions live entirely in `rpcd`'s memory. They are not written to disk and do not survive a reboot or a restart of `rpcd`. Upgrading or downgrading `luci-sso` leaves `rpcd` alone, so sessions survive it; removing the package restarts `rpcd` to revoke its settings ACL at once, which ends every session — see [How to Upgrade luci-sso](../how-to/sysadmin/upgrade.md) and [How to Remove luci-sso](../how-to/sysadmin/uninstall.md).

A *reload* of `rpcd` is different, and it affects SSO sessions only. On a reload, `rpcd` keeps every session and its values but rebuilds each session's rights from its own login configuration (`/etc/config/rpcd`), keyed by the session's user name. Password sessions get their rights back. SSO sessions have no entry there, so they come back logged in but with no rights at all, and every LuCI page then fails with access errors until the user logs in again. LuCI's own packages reload `rpcd` when they are installed or upgraded, so installing or upgrading any LuCI app has this effect on everyone logged in through SSO.

Multiple simultaneous sessions are allowed. Each login creates a new independent UBUS session with its own ID and idle timeout. `rpcd` can list every session with its values, and SSO sessions carry the user's email as `oidc_user`, so an administrator can find one user's sessions and destroy just those. Restarting `rpcd` instead evicts every session, password logins included.

---

## Summary

| Property | Value |
| :--- | :--- |
| Session store | UBUS / `rpcd` (in-memory) |
| Session lifetime | Idle timeout from `luci.sauth.sessiontime` (default 3600 s), reset on every request |
| Token expiry effect | Validated at login only; does not shorten or extend session |
| Mid-session IdP revocation | Session continues until expiry, logout, or an administrator destroys it |
| Logout scope | Destroys the router session; IdP session is separate |
| Persistence across reboots | No — UBUS sessions are in-memory |
| Persistence across a `luci-sso` upgrade | Yes — only removal restarts `rpcd` |
| Effect of an `rpcd` reload (e.g. installing a LuCI app) | SSO sessions stay but lose all rights; users must log in again |
