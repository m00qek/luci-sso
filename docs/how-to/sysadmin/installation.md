# How to Install luci-sso

This guide describes how to install `luci-sso` and its crypto backend on your OpenWrt router.

`luci-sso` is two packages: `luci-sso` itself, plus **exactly one** crypto backend package. `luci-sso` depends on a virtual `luci-sso-crypto` package that each backend provides, so the package manager will not install it alone, and will not pick a backend for you. All three backends install the same file, `/usr/lib/ucode/luci_sso/native.so`, so installing more than one fails.

---

## 1. Choose a crypto backend

| Package | Library it uses |
| :--- | :--- |
| `luci-sso-crypto-mbedtls` | mbedTLS |
| `luci-sso-crypto-wolfssl` | wolfSSL |
| `luci-sso-crypto-openssl` | OpenSSL |

Use **mbedTLS** unless you have a reason not to: it is lightweight and already present on most OpenWrt systems. Use **wolfSSL** as an alternative lightweight option, or **OpenSSL** if the router already uses it for other services such as VPNs. The package manager installs the library from the OpenWrt feeds if it is missing. For the trade-offs, see [About Crypto Backends](../../explanation/crypto-backends.md).

---

## 2. Get the packages

Build them as described in [Building from Source](../../tutorials/building.md). On OpenWrt 24.10 the build leaves `.ipk` files in `bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/`, next to every other package the SDK built. You need two of them:

```text
luci-sso_<version>_<arch>.ipk
luci-sso-crypto-mbedtls_<version>_<arch>.ipk
```

OpenWrt 25.12 uses `apk` packages instead, named `luci-sso-<version>.apk` and `luci-sso-crypto-mbedtls-<version>.apk`. The build does not copy them out yet; see [Building from Source](../../tutorials/building.md#step-3-find-the-packages).

---

## 3. Install the packages

=== "Browser (LuCI)"

    These steps are for OpenWrt 24.10. On 25.12, use the terminal.

    1.  **Log in** to your router's LuCI web interface.
    2.  Navigate to **System** -> **Software**.

    ![LuCI interface showing the Software page with the 'Update lists...' and 'Upload Package...' buttons highlighted](../../assets/screenshots/luci-software-install.svg "LuCI Software installation page")

    3.  Click **Update lists...** so the backend's crypto library can be installed from the OpenWrt feeds.
    4.  Click **Upload Package...**, select the backend file (for example `luci-sso-crypto-mbedtls_<version>_<arch>.ipk`) and confirm the installation.
    5.  Click **Upload Package...** again, select the `luci-sso_<version>_<arch>.ipk` file and confirm. The backend must already be installed: `luci-sso` cannot be installed without one.

=== "Terminal (SSH)"

    1.  **Copy the two packages to the router**, for example with `scp` from the build machine:

        ```bash
        scp -O luci-sso_<version>_<arch>.ipk luci-sso-crypto-mbedtls_<version>_<arch>.ipk root@192.168.1.1:/tmp/
        ```

    2.  **Install both in one command** on the router.

        On OpenWrt 24.10 (`opkg`):

        ```bash
        opkg update
        opkg install /tmp/luci-sso_<version>_<arch>.ipk /tmp/luci-sso-crypto-mbedtls_<version>_<arch>.ipk
        ```

        On OpenWrt 25.12 (`apk`):

        ```bash
        apk update
        apk add --allow-untrusted /tmp/luci-sso-<version>.apk /tmp/luci-sso-crypto-mbedtls-<version>.apk
        ```

        `--allow-untrusted` is needed because packages you built yourself are not signed with a key the router trusts; without it `apk` stops with `UNTRUSTED signature`.

Installing runs the package's setup scripts once: they create `/var/run/luci-sso/`, add a daily cleanup job to root's crontab, and add the SSO button to LuCI's login page templates.

### Switch to a different backend later

Remove the old backend without removing `luci-sso`, then install the new one:

```bash
opkg remove --force-depends luci-sso-crypto-mbedtls
opkg install /tmp/luci-sso-crypto-openssl_<version>_<arch>.ipk
```

---

## 4. Verify the installation

The package ships with SSO turned off (`enabled '0'`), so right after installation the probe answers `false`. That answer shows the CGI script and the crypto backend are working.

=== "Browser (LuCI)"

    Navigate to the following URL in your browser:
    `https://192.168.1.1/cgi-bin/luci-sso?action=enabled`

    It should return a JSON response: `{"enabled": false}`.

=== "Terminal (SSH)"

    Run the CGI script directly on the router:

    ```bash
    QUERY_STRING="action=enabled" /www/cgi-bin/luci-sso
    ```

    **Expected output** (the security headers are left out here):

    ```http
    Status: 200 OK
    Content-Type: application/json

    {"enabled": false}
    ```

The probe answers `{"enabled": true}` once you have configured an identity provider and turned SSO on.

---

## Next Steps

Configure `luci-sso` with an identity provider:

- **[Your First SSO Login: Public IdP](../../tutorials/first-sso-login.md)** — Google. Requires a domain name and a publicly trusted certificate.
- **[Your First SSO Login: Self-hosted IdP](../../tutorials/pocket-id-sso-login.md)** — Pocket ID on your LAN. No public infrastructure required.

If you already know which provider you are using, go directly to the [How-to Guides](../index.md#identity-providers) for provider-specific configuration.
