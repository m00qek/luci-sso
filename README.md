# LuCI SSO (Beta)

[![Continuous Integration](https://github.com/m00qek/luci-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/m00qek/luci-sso/actions/workflows/ci.yml)
[![Publish Docs](https://github.com/m00qek/luci-sso/actions/workflows/docs.yml/badge.svg)](https://github.com/m00qek/luci-sso/actions/workflows/docs.yml)
[![License: MIT](https://img.shields.io/github/license/m00qek/luci-sso?color=blue)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange)](#)
[![OpenWrt Compatibility](https://img.shields.io/badge/OpenWrt-24.10%20%7C%2025.12-blue?logo=openwrt)](#)
[![Built with ucode](https://img.shields.io/badge/Built%20with-ucode-green)](#)

**Secure, Lightweight OIDC/OAuth2 Login for OpenWrt LuCI.**

<img width="1119" height="588" alt="LuCI web interface login screen showing a blue 'Login with SSO' button prominently displayed above the standard OpenWrt password prompt." src="https://github.com/user-attachments/assets/cbe996a7-fc25-4f63-bd91-0d57dddcab75" />

---

## What is this?

`luci-sso` replaces the standard LuCI password prompt with an **OpenID Connect (OIDC)** flow, letting you secure your router with identity providers like Google, GitHub, or Authelia.

## Documentation

### [Read the Documentation](https://m00qek.github.io/luci-sso/)

*   **[Tutorials](https://m00qek.github.io/luci-sso/tutorials/)**: Start here — [Your First SSO Login](https://m00qek.github.io/luci-sso/tutorials/first-sso-login/) walks you through a complete setup in minutes.
*   **[How-to Guides](https://m00qek.github.io/luci-sso/how-to/)**: Provider configuration, RBAC, split-horizon, debugging, and more.
*   **[Reference](https://m00qek.github.io/luci-sso/reference/)**: UCI schema, HTTP API, log messages, and RFC compliance.
*   **[Explanation](https://m00qek.github.io/luci-sso/explanation/)**: Architecture, security model, OIDC flow, and threat model.

---

## Quick Build

If you have Docker and `make`:

```bash
make package SDK_ARCH=x86-64
```

See [Building from Source](https://m00qek.github.io/luci-sso/tutorials/building/) for other architectures.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
