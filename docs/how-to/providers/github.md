# GitHub is Not a Supported Provider

GitHub OAuth Apps are **not compatible** with `luci-sso`. This page explains why.

---

## Why GitHub does not work

`luci-sso` implements strict OIDC Core 1.0. GitHub's OAuth2 service fails two mandatory requirements:

**1. No OIDC discovery.**
`luci-sso` fetches `<issuer_url>/.well-known/openid-configuration` to locate the token endpoint and JWKS, and caches it for 24 hours. GitHub does not serve this document — the request returns a 404. The login fails immediately with `OIDC_DISCOVERY_FAILED` before any credentials are exchanged.

**2. No ID Token.**
`luci-sso` identifies the user from a signed ID Token, and requires that token to carry an `at_hash` claim binding it to the access token. GitHub OAuth Apps return an access token only, with no ID Token. A login that somehow passed discovery would fail with `ID_TOKEN_VERIFICATION_FAILED`, detail `MISSING_ID_TOKEN`.

---

## Alternatives

If you need SSO backed by GitHub identity, place an OIDC provider that can sign users in through GitHub in front of it:

- **[Dex](generic-oidc.md)** — An OIDC bridge that can federate GitHub, Google, and LDAP behind a single compliant issuer. Use the generic OIDC guide after configuring Dex.

Dex handles the GitHub OAuth2 handshake on its side and issues its own OIDC tokens to `luci-sso`. Check that its ID Tokens include `at_hash`, as the [generic guide's prerequisites](generic-oidc.md#prerequisites) require.
