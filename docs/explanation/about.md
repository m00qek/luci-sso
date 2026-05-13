# About LuCI SSO

**LuCI SSO** is a secure, lightweight OIDC/OAuth2 login provider for the OpenWrt web interface (LuCI).

<img width="1119" height="588" alt="LuCI web interface login screen showing a blue 'Login with SSO' button prominently displayed above the standard OpenWrt password prompt." src="https://github.com/user-attachments/assets/cbe996a7-fc25-4f63-bd91-0d57dddcab75" />

---

## 📖 Overview

It replaces the standard LuCI password prompt with a modern **OpenID Connect (OIDC)** flow. This allows you to manage access to your router using external identity providers like Google, GitHub, or Authelia.

### Why use this?
*   **Security First:** Full PKCE (S256) support, Strict HTTPS enforcement, Anti-Replay protection, and Token Binding.
*   **Lightweight:** Written in pure **ucode** with a tiny C bridge for crypto. No Python/Node.js/Go dependencies on the router.
*   **Native Integration:** Uses `ubus` session injection. No hacks, no proxy servers.
*   **Split-Horizon Support:** Supports environments where the Router and Browser see the IdP at different URLs (common in home labs).

### Terminology
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).
