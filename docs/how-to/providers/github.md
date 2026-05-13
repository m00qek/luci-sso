# GitHub is Not a Supported Provider

GitHub OAuth Apps are **not compatible** with `luci-sso`. This page explains why.

---

## Why GitHub does not work

`luci-sso` implements strict OIDC Core 1.0. GitHub's OAuth2 service fails two mandatory requirements:

**1. No OIDC discovery.**
`luci-sso` fetches `<issuer_url>/.well-known/openid-configuration` on every login to locate the token endpoint and JWKS. GitHub does not serve this document — the request returns a 404. The login fails immediately with `OIDC_DISCOVERY_FAILED` before any credentials are exchanged.

**2. No `at_hash` claim.**
`luci-sso` enforces access token binding: the ID Token must contain an `at_hash` claim whose value is the base64url-encoded first half of SHA256 of the access token. This check is mandatory and cannot be disabled. GitHub OAuth2 token responses do not include `at_hash`. Any login attempt that somehow passed discovery would fail with `MISSING_AT_HASH`.

---

## Alternatives

If you need SSO backed by GitHub identity, place a full OIDC provider in front of GitHub's OAuth2:

- **[Authelia](authelia.md)** — Supports GitHub as a social upstream while exposing a fully compliant OIDC interface to `luci-sso`.
- **[Dex](generic-oidc.md)** — An OIDC bridge that can federate GitHub, Google, and LDAP behind a single compliant issuer. Use the generic OIDC guide after configuring Dex.

These providers handle the GitHub OAuth2 handshake on their side and issue properly formed OIDC tokens — including `at_hash` — to `luci-sso`.
