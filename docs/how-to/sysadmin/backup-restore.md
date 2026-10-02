# How to Back Up and Restore luci-sso Configuration

This guide covers preserving your `luci-sso` configuration across a router reflash or factory reset, and restoring it afterwards.

---

## What needs backing up

| Item | Location | Backed up by OpenWrt? | Notes |
| :--- | :--- | :--- | :--- |
| UCI configuration | `/etc/config/luci-sso` | Yes — included in the standard sysupgrade backup | Contains IdP credentials, the roles (who matches each one, and their order), and all UCI options. |
| Role permissions | The `luci_sso_*` login entries in `/etc/config/rpcd` | Yes — `/etc/config/rpcd` is in the standard sysupgrade backup | Each role's read and write access. `/etc/config/rpcd` also holds the `root` login. |
| Runtime state | `/var/run/luci-sso/` | No — tmpfs, not persistent | Discovery and JWK Set caches, logins in progress, token registry, rate-limit state. Rebuilt automatically as needed. |
| Active sessions | UBUS memory | No | Sessions do not survive a reboot regardless. |
| The `luci-sso` packages | `/usr/share/ucode/luci_sso/`, `/www/cgi-bin/luci-sso` and others | No | A firmware image only contains the packages it was built with. Keep the package files so you can reinstall them. |

Back up `/etc/config/luci-sso` and `/etc/config/rpcd` together. Everything else is either reinstalled, regenerated automatically, or does not survive a reboot anyway.

The two files belong together. Restoring `/etc/config/luci-sso` without the matching `rpcd` entries leaves roles without permissions: their users are refused at login with `MISSING_RPCD_LOGIN`. Restoring the `rpcd` entries without the roles leaves entries that no role uses.

---

## Back up the configuration

=== "Browser (LuCI)"

    LuCI's standard backup includes `/etc/config/luci-sso` automatically.

    1. Navigate to **System > Backup / Flash Firmware**.
    2. Click **Generate archive** under the **Backup** section.
    3. Save the downloaded `.tar.gz` file somewhere safe.

=== "Terminal (SSH)"

    Copy the two configuration files to your local machine:

    ```bash
    scp -O root@192.168.1.1:/etc/config/luci-sso ./luci-sso.backup
    scp -O root@192.168.1.1:/etc/config/rpcd ./rpcd.backup
    ```

    Or include it in a full config backup:

    ```bash
    ssh root@192.168.1.1 'sysupgrade --create-backup -' > router-backup.tar.gz
    ```

---

## Restore the configuration

### After a sysupgrade (firmware update)

`sysupgrade` preserves `conffiles` — files the package declares as configuration. `/etc/config/luci-sso` is declared as a conffile, and `/etc/config/rpcd` belongs to the base system, so both survive a sysupgrade automatically.

The package itself does not. The new firmware contains only the packages it was built with, so after the sysupgrade `luci-sso` is gone and the login page has no SSO button. Reinstall `luci-sso` and its crypto backend, built for the new OpenWrt version (see [How to Install luci-sso](installation.md)). The reinstall keeps the preserved `/etc/config/luci-sso` and saves the package's default next to it as `/etc/config/luci-sso-opkg` (`luci-sso.apk-new` on OpenWrt 25.12), which you can delete.

### After a factory reset or reflash

**Step 1.** Re-install the `luci-sso` package (see [How to Install luci-sso](installation.md)).

**Step 2.** Restore the configuration file:

=== "Browser (LuCI)"

    1. Navigate to **System > Backup / Flash Firmware**.
    2. Click **Restore backup** and upload the `.tar.gz` archive you saved earlier.
    3. LuCI will extract the archive and restore `/etc/config/luci-sso` and `/etc/config/rpcd` along with all other backed-up config files.
    4. Reboot when prompted.

=== "Terminal (SSH)"

    Copy your backup files back to the router:

    ```bash
    scp -O luci-sso.backup root@192.168.1.1:/etc/config/luci-sso
    scp -O rpcd.backup root@192.168.1.1:/etc/config/rpcd
    ```

    Reload `rpcd` so it reads the restored entries, then verify the configuration loaded correctly:

    ```bash
    ssh root@192.168.1.1 '/etc/init.d/rpcd reload; uci show luci-sso; uci show rpcd | grep luci_sso_'
    ```

    `rpcd` should have one `luci_sso_<role>` entry for each role in `/etc/config/luci-sso`. If a role has none, save it on the settings page, which gives it one, or create it with `uci`; see [How to Configure Role-Based Access Control](rbac.md#where-to-change-a-role).

**Step 3.** Verify the service is working. On the router:

--8<-- "probe-enabled.md"

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
