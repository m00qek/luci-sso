# About Crypto Backends

`luci-sso` relies on a native C bridge to perform cryptographic operations like JWT verification, hashing, and secure random number generation. Because OpenWrt runs on a vast range of hardware with different storage and memory constraints, `luci-sso` supports three different cryptographic backends.

---

## Why multiple backends?

OpenWrt is a constrained environment. A router might have as little as 4MB or 8MB of flash storage. In such cases, every kilobyte counts. Conversely, a powerful x86-based router might prioritize performance or need to adhere to specific security standards (like FIPS) provided by OpenSSL.

By supporting multiple backends, `luci-sso` allows you to:
1.  **Minimize Flash Usage:** Use a library that is already present on your system.
2.  **Optimize Performance:** Choose a backend that is optimized for your CPU architecture.
3.  **Ensure Consistency:** Align with the security policy of your organization.

---

## Comparison of Backends

| Backend | Primary Use Case | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **mbedTLS** | **Default / Low Flash** | Smallest footprint; extremely common in OpenWrt. | Generally slower than OpenSSL on high-end hardware. |
| **wolfSSL** | **Lightweight / Speed** | Very fast and very small; modern cipher support. | Not as universally present as mbedTLS in base OpenWrt. |
| **OpenSSL** | **Enterprise / Full-stack** | Highest performance; feature-rich; FIPS support. | Very large binary size; high memory usage. |

### [mbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/)
mbedTLS (formerly PolarSSL) is the standard lightweight crypto library for OpenWrt. If you are unsure which backend to choose, **use mbedTLS**. Most OpenWrt services (like `uhttpd` with SSL) already pull in `libmbedtls`, so choosing this backend often adds zero additional flash overhead.

### [wolfSSL](https://www.wolfssl.com/)
wolfSSL is designed for embedded systems where performance is critical but flash space is still tight. It is often faster than mbedTLS while maintaining a similar footprint. It is an excellent choice for users who want a balance between efficiency and speed.

### [OpenSSL](https://www.openssl.org/)
OpenSSL is the industry standard. While it is the most performant and feature-complete, its binary size is significant. It is typically only recommended for OpenWrt systems with plenty of flash (e.g., 32MB+) or systems that already require OpenSSL for other services like OpenVPN or complex Nginx configurations.

---

## The Native Bridge Architecture

`luci-sso` does not interact with these libraries directly from its core logic. Instead, it uses a **Native Bridge** pattern.

1.  **Core Logic (ucode):** All OIDC and session logic is written in `ucode`. When it needs to verify a signature, it calls a generic `luci_sso.native` module.
2.  **Native Interface (C):** A thin C layer defines a consistent API for `ucode`.
3.  **Backends (C):** Three separate shared objects (`native_mbedtls.so`, `native_wolfssl.so`, `native_openssl.so`) implement that API.

At installation time, the `luci-sso-crypto-*` package you choose installs the corresponding `.so` file to `/usr/lib/ucode/luci_sso/native.so`. This allows the high-level code to remain entirely agnostic of which library is actually doing the work.

If you need to implement support for a library not listed here, see [How to Add a New Crypto Backend](../how-to/developer/adding-crypto-backend.md).

---

## Performance vs. Size

The choice of backend is ultimately a trade-off between **Binary Size** and **Execution Speed**.

For a single login flow, the difference in execution time (e.g., 10ms vs 50ms) is usually imperceptible to a human user. However, on low-power MIPS or ARM CPUs, the RSA/EC verification performed during a JWT check is the most CPU-intensive part of the entire login process. 

If you find that the SSO login feels "sluggish" on very old hardware, switching from mbedTLS to wolfSSL or OpenSSL *may* provide a slight improvement, provided you have the flash space to spare.
