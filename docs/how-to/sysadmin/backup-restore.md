# How to Back Up and Restore luci-sso Configuration

This guide covers preserving your `luci-sso` configuration across a router reflash or factory reset, and restoring it afterwards.

---

## What needs backing up

| Item | Location | Backed up by OpenWrt? | Notes |
| :--- | :--- | :--- | :--- |
| UCI configuration | `/etc/config/luci-sso` | Yes — included in the standard sysupgrade backup | Contains IdP credentials, role mappings, and all UCI options. |
| Runtime state | `/var/run/luci-sso/` | No — tmpfs, not persistent | Discovery cache and token registry. Rebuilt automatically on next login. |
| Active sessions | UBUS memory | No | Sessions do not survive a reboot regardless. |
| The `luci-sso` packages | `/usr/share/ucode/luci_sso/`, `/www/cgi-bin/luci-sso` and others | No | A firmware image only contains the packages it was built with. Keep the package files so you can reinstall them. |

The only file you must back up is `/etc/config/luci-sso`. Everything else is either reinstalled, regenerated automatically, or does not survive a reboot anyway.

---

## Back up the configuration

=== "Browser (LuCI)"

    LuCI's standard backup includes `/etc/config/luci-sso` automatically.

    1. Navigate to **System > Backup / Flash Firmware**.
    2. Click **Generate archive** under the **Backup** section.
    3. Save the downloaded `.tar.gz` file somewhere safe.

=== "Terminal (SSH)"

    Copy the configuration file to your local machine:

    ```bash
    scp -O root@192.168.1.1:/etc/config/luci-sso ./luci-sso.backup
    ```

    Or include it in a full config backup:

    ```bash
    ssh root@192.168.1.1 'sysupgrade --create-backup -' > router-backup.tar.gz
    ```

---

## Restore the configuration

### After a sysupgrade (firmware update)

`sysupgrade` preserves `conffiles` — files the package declares as configuration. `/etc/config/luci-sso` is declared as a conffile, so your configuration survives a sysupgrade automatically.

The package itself does not. The new firmware contains only the packages it was built with, so after the sysupgrade `luci-sso` is gone and the login page has no SSO button. Reinstall `luci-sso` and its crypto backend, built for the new OpenWrt version (see [How to Install luci-sso](installation.md)). The reinstall keeps the preserved `/etc/config/luci-sso` and saves the package's default next to it as `/etc/config/luci-sso-opkg` (`luci-sso.apk-new` on OpenWrt 25.12), which you can delete.

### After a factory reset or reflash

**Step 1.** Re-install the `luci-sso` package (see [How to Install luci-sso](installation.md)).

**Step 2.** Restore the configuration file:

=== "Browser (LuCI)"

    1. Navigate to **System > Backup / Flash Firmware**.
    2. Click **Restore backup** and upload the `.tar.gz` archive you saved earlier.
    3. LuCI will extract the archive and restore `/etc/config/luci-sso` along with all other backed-up config files.
    4. Reboot when prompted.

=== "Terminal (SSH)"

    Copy your backup file back to the router:

    ```bash
    scp -O luci-sso.backup root@192.168.1.1:/etc/config/luci-sso
    ```

    Then verify the configuration loaded correctly:

    ```bash
    uci show luci-sso
    ```

**Step 3.** Verify the service is working. On the router:

```bash
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
# Expected: {"enabled": true}
```

Attempt a login to confirm the IdP credentials are still valid. If the client secret has been rotated at the IdP since the backup was made, update it before testing:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**. Update **Client Secret**, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.client_secret='NEW_SECRET'
    uci commit luci-sso
    ```

---

## Related guides

- [How to Upgrade luci-sso](upgrade.md) — for upgrading the package without a full reflash.
- [How to Rotate Credentials](rotate-credentials.md) — if the backed-up client secret needs updating after restore.
