# LuCI SSO (Beta)

**Secure, Lightweight OIDC/OAuth2 Login for OpenWrt LuCI.**

---

## 📖 What is this?
`luci-sso` replaces the standard LuCI password prompt with an **OpenID Connect (OIDC)** flow, allowing you to secure your router with modern identity providers like Google, GitHub, or Authelia.

## 📚 Documentation
Our documentation is organized using the **Diataxis Framework** to serve different personas (Users, Sysadmins, Auditors, Developers, and AI Agents).

### [👉 Read the Documentation](https://m00qek.github.io/luci-sso/)

*   **[Tutorials](https://m00qek.github.io/luci-sso/tutorials/)**: Building from source and getting started.
*   **[How-to Guides](https://m00qek.github.io/luci-sso/how-to/)**: Configuring providers and debugging.
*   **[Reference](https://m00qek.github.io/luci-sso/reference/)**: UCI schemas and RFC compliance.
*   **[Explanation](https://m00qek.github.io/luci-sso/explanation/)**: Architecture and Security Model deep-dives.

---

## 🚀 Quick Build
If you have Docker and `make`, you can build the package for your architecture immediately:

```bash
make package SDK_ARCH=x86-64
```

See [Building from Source](https://m00qek.github.io/luci-sso/tutorials/building/) for other architectures.

---

## 📜 License
MIT License. See [LICENSE](LICENSE) for details.
