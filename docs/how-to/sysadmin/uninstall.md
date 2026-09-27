# How to Remove luci-sso

This guide covers completely removing `luci-sso` from your router and restoring the standard LuCI password login.

!!! warning "Removal logs everyone out"
    Removing `luci-sso` restarts `rpcd`, which ends every LuCI session: SSO users, password users, and you, if you are removing it from LuCI. Before you start, make sure you can log in with the `root` password, or use SSH, which is not affected.

---

## What removal does

Removing the `luci-sso` package deletes its files, including its override of LuCI's **Log out** entry, so LuCI's own logout is back. It also runs its removal script, which:

- takes the cleanup job out of root's crontab,
- removes the SSO button from LuCI's login templates, in every theme (`luci-sso-repatch --remove`),
- deletes the `luci-app-sso` access group and restarts `rpcd`, which ends every LuCI session,
- clears LuCI's cache.

The crypto backend is a separate package and has to be removed as well. `luci-sso` depends on it, so remove `luci-sso` first, or both in one command.

---

## Step 1: Remove the packages

=== "Terminal (SSH)"

    On OpenWrt 24.10:

    ```bash
    opkg remove luci-sso luci-sso-crypto-mbedtls
    ```

    On OpenWrt 25.12:

    ```bash
    apk del luci-sso luci-sso-crypto-mbedtls
    ```

    If you installed a different backend, replace `luci-sso-crypto-mbedtls` with the one you used (for example `luci-sso-crypto-wolfssl`).

=== "Browser (LuCI)"

    1.  **Log in** to your router's LuCI web interface with the `root` password.
    2.  Navigate to **System** -> **Software** and click the **Installed** tab.
    3.  In the **Filter** box, type `luci-sso`.
    4.  Click **Remove** next to `luci-sso`. LuCI logs you out while the package is removed.
    5.  Log in again with the `root` password, return to **System** -> **Software**, and click **Remove** next to your crypto backend (for example `luci-sso-crypto-mbedtls`).

    ![LuCI Software page showing the 'Installed' tab and the filter box used to find luci-sso packages](../../assets/screenshots/luci-software-uninstall.svg "Removing packages via LuCI")

---

## Step 2: Confirm the login page is restored

Navigate to `https://<YOUR_ROUTER>/cgi-bin/luci/`. The SSO button should be gone, and only the standard username and password fields should be visible.

If the SSO button is still showing, your browser may be using a cached copy of the page. Clear the browser's cache for the router's address and reload. On the router, you can also clear LuCI's cache again:

```bash
rm -rf /tmp/luci-modulecache/ /tmp/luci-indexcache*
```

---

## Step 3: Clean up remaining files (optional)

Removal leaves a few files behind:

- **Configuration** — if you changed `/etc/config/luci-sso`, the package manager keeps it. An unchanged file is removed with the package. To delete a kept file:

    ```bash
    rm /etc/config/luci-sso
    ```

- **Package feed** — if you installed from the package feed, remove it and its signing key so the package manager stops using it. On OpenWrt 24.10:

    ```bash
    sed -i '/packages.ucode.dev/d' /etc/opkg/customfeeds.conf
    rm -f /etc/opkg/keys/a2288d4745630a38
    ```

    On OpenWrt 25.12:

    ```bash
    sed -i '/packages.ucode.dev/d' /etc/apk/repositories.d/customfeeds.list
    rm -f /etc/apk/keys/packages.ucode.dev.pem
    ```

- **Leftover key from older versions** — older releases created `/etc/luci-sso/secret.key` on first login. Current versions neither create nor read it. If the directory exists, it is safe to delete:

    ```bash
    rm -rf /etc/luci-sso
    ```

- **Runtime state** — `/var/run/luci-sso/` (discovery cache, token registry, rate-limit state) disappears on the next reboot. To clear it immediately:

    ```bash
    rm -rf /var/run/luci-sso
    ```

- **Empty module directories** — `/usr/share/ucode/luci_sso/` and `/usr/lib/ucode/luci_sso/` may remain, empty. They are harmless; delete them if you like:

    ```bash
    rm -rf /usr/share/ucode/luci_sso /usr/lib/ucode/luci_sso
    ```

- **Custom CA certificates** — if you added a private CA certificate for a self-hosted IdP, and nothing else on the router needs it, remove it:

    ```bash
    rm /etc/ssl/certs/my-homelab-ca.crt
    ```

    There is no certificate store to rebuild: `luci-sso` reads the files in `/etc/ssl/certs/` directly.
