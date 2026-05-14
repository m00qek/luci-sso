# About LuCI SSO

**LuCI SSO** is a secure, lightweight OIDC/OAuth2 login provider for the OpenWrt web interface (LuCI).

<img width="1119" height="588" alt="LuCI web interface login screen showing a blue 'Login with SSO' button prominently displayed above the standard OpenWrt password prompt." src="https://github.com/user-attachments/assets/cbe996a7-fc25-4f63-bd91-0d57dddcab75" />

---

## The problem it solves

LuCI's built-in authentication uses local Unix passwords. In practice, most routers are configured with a single shared `root` account — adding per-user accounts is possible but cumbersome, and LuCI provides no first-class support for it. This creates several problems that become acute as home lab and self-hosted setups grow more sophisticated:

**No identity.** A shared password provides no way to distinguish who made a change, grant different levels of access to different people, or revoke one person's access without resetting the password for everyone.

**Credential sprawl.** A router password is another credential to manage separately from the identity system already used for everything else in the network — Authelia, Keycloak, a corporate IdP. Every separately managed credential is a weak link.

**Brute-force exposure.** Routers are frequently exposed to the internet or sit at the edge of networks that are. The LuCI password endpoint is a standard target for automated credential-stuffing attacks. Password authentication over the management interface is a persistent attack surface.

OIDC solves all three. A single click delegates authentication to the identity provider already trusted for the rest of the network. The IdP returns an identity — an email address and group memberships — that `luci-sso` maps to router access levels. Rotating a credential, revoking a user, or enforcing MFA happens at the IdP; the router's configuration does not need to change.

---

## Why not an existing solution?

The obvious answer — run an OIDC reverse proxy in front of LuCI — requires a separate machine, adds a proxy to the path for every page load, and does not integrate with LuCI's native session model. The result is a brittle dependency on external infrastructure for every management action, including diagnosing the network failure that took the proxy offline.

`luci-sso` is a native OpenWrt package. It runs directly on the router, uses LuCI's existing UBUS session injection, and adds no runtime dependencies beyond the crypto library already present on the device. If the IdP is unreachable, the standard password login still works at `/cgi-bin/luci/admin/` — SSO is additive, not a replacement.

---

## The constraints that shaped it

OpenWrt routers are constrained hardware. A typical device has 64 MB of RAM and 16 MB of flash storage. These limits rule out the runtimes that OIDC libraries are typically written in: no Python, no Node.js, no Go. Every dependency is flash storage consumed and RAM consumed.

`luci-sso` is written in **ucode** — OpenWrt's native scripting language — with a thin C bridge for the cryptographic operations that require guaranteed memory behavior (constant-time comparisons, buffer zeroization). The C bridge is the only compiled component; everything else is interpreted ucode loaded on demand.

The same embedded constraints make testing difficult: you cannot run an integration test against a real IdP on a router that has no network interface to your test infrastructure. The architecture's strict separation between pure logic and I/O — the Functional Core / Imperative Shell pattern — exists specifically to make every authentication code path testable offline with a mock environment. See [About the Architecture](architecture.md) for how that separation is structured.

---

## Current status

`luci-sso` is in **Beta**. It is functional and deployed in home lab and self-hosted environments, but the API surface — UCI configuration options, log message codes, internal module interfaces — may change between versions. Compatibility is not guaranteed across minor versions until a stable release is tagged.

Specifically:

- The UCI configuration schema (`/etc/config/luci-sso`) is stable for the options documented in the [UCI Configuration Reference](../reference/uci-config.md).
- The LuCI web interface for configuration does not yet exist — all setup requires SSH. This is the primary remaining gap before a stable release.
- The crypto backend interface (`src/native.h`) is stable for the functions documented in the [Internal API Reference](../reference/internal-api.md).

The project targets **OpenWrt 24.10** and **25.12**.

---

## Further reading

- [Design Philosophy](design-philosophy.md) — The principles behind the security and architecture decisions.
- [About the Architecture](architecture.md) — How the Functional Core / Imperative Shell pattern is implemented.
- [Security Model](security-model.md) — The paranoid baseline and why each protection exists.
- [Threat Model](threat-model.md) — The specific attacks the design addresses.
