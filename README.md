# LuCI SSO (Beta)

[![Continuous Integration](https://github.com/m00qek/luci-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/m00qek/luci-sso/actions/workflows/ci.yml)
[![Publish Docs](https://github.com/m00qek/luci-sso/actions/workflows/docs.yml/badge.svg)](https://github.com/m00qek/luci-sso/actions/workflows/docs.yml)
[![License: MIT](https://img.shields.io/github/license/m00qek/luci-sso?color=blue)](LICENSE)
[![Status: Beta](https://img.shields.io/badge/status-beta-orange)](#)
[![OpenWrt Compatibility](https://img.shields.io/badge/OpenWrt-24.10%20%7C%2025.12-blue?logo=openwrt)](#)
[![Built with ucode](https://img.shields.io/badge/Built%20with-ucode-green)](#)

**Secure, Lightweight OIDC/OAuth2 Login for OpenWrt LuCI.**

<img width="1119" height="588" alt="LuCI web interface login screen showing the standard OpenWrt username and password fields with a 'Login with SSO' button added below the Log in button." src="https://github.com/user-attachments/assets/cbe996a7-fc25-4f63-bd91-0d57dddcab75" />

---

## What is this?

`luci-sso` adds an **OpenID Connect (OIDC)** sign-in option to the LuCI login page, so you can log in to your router through identity providers like Google, Keycloak, Authentik, Authelia or Pocket ID. The standard password login stays available.

## Documentation

### [Read the Documentation](https://m00qek.github.io/luci-sso/latest/)

*   **[Tutorials](https://m00qek.github.io/luci-sso/latest/tutorials/)**: Start here — [Your First SSO Login](https://m00qek.github.io/luci-sso/latest/tutorials/first-sso-login/) walks you through a complete setup in minutes.
*   **[How-to Guides](https://m00qek.github.io/luci-sso/latest/how-to/)**: Provider configuration, RBAC, split-horizon, debugging, and more.
*   **[Reference](https://m00qek.github.io/luci-sso/latest/reference/)**: UCI schema, HTTP API, log messages, and RFC compliance.
*   **[Explanation](https://m00qek.github.io/luci-sso/latest/explanation/)**: Architecture, security model, OIDC flow, and threat model.

---

## Quick Install

Signed packages are published for OpenWrt 24.10 and 25.12 on `x86_64`, `aarch64_generic` and `aarch64_cortex-a53`. On an OpenWrt 24.10 router:

```bash
wget -O /tmp/feed.pub https://m00qek.github.io/packages.ucode.dev/24.10/feed.pub
cp /tmp/feed.pub "/etc/opkg/keys/$(usign -F -p /tmp/feed.pub)"
echo 'src/gz ucode.dev https://m00qek.github.io/packages.ucode.dev/24.10' >> /etc/opkg/customfeeds.conf
opkg update && opkg install luci-sso luci-sso-crypto-mbedtls
```

For OpenWrt 25.12 (`apk`) and the other steps, see [How to Install luci-sso](https://m00qek.github.io/luci-sso/latest/how-to/sysadmin/installation/).

## Build from Source

For other architectures, or to try your own changes, build the packages with Docker and `make`:

```bash
make package SDK_ARCH=x86-64
```

See [How to Build the Packages from Source](https://m00qek.github.io/luci-sso/latest/how-to/sysadmin/build-from-source/).

---

## License

MIT License. See [LICENSE](LICENSE) for details.
