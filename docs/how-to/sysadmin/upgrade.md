# How to Upgrade luci-sso

This guide walks through upgrading an existing `luci-sso` installation to a new version, restoring the SSO button after a LuCI upgrade, and rolling back.

!!! note "Sessions survive an upgrade"
    Installing a newer or older `luci-sso` package over the installed one keeps every LuCI session, SSO and password logins alike. Only a real removal, or `opkg install --force-reinstall` on OpenWrt 24.10, restarts `rpcd` and logs everyone out.

---

## What persists across an upgrade

| Item | Persists? | Notes |
| :--- | :--- | :--- |
| `/etc/config/luci-sso` | ✅ Yes | Declared as a `conffile`. If you changed it, your version is kept and the new default is saved next to it as `/etc/config/luci-sso-opkg` (`luci-sso.apk-new` on OpenWrt 25.12). |
| Active LuCI sessions | ✅ Yes | An upgrade or downgrade does not restart `rpcd`. On OpenWrt 24.10, upgrading *from* a release that predates this behaviour still logs everyone out once, because opkg runs the old release's removal script. |
| `/var/run/luci-sso/` | ✅ Until reboot | This is a tmpfs directory. Its contents survive the upgrade but are cleared on the next reboot. |
| Token registry entries | ✅ Until reboot | Expired entries are removed by the daily cleanup job, not by the upgrade. |
| SSO button on the login page | ✅ Yes | The removal script takes it out of LuCI's templates, and the install script puts it back. |
| SSO logout from LuCI's **Log out** entry | ✅ Yes | A menu override in the package (`/usr/share/luci/menu.d/luci-sso-logout.json`), not a patch, so it also survives a LuCI upgrade. |

---

## Step 1: Check the current version

On OpenWrt 24.10:

```bash
opkg list-installed luci-sso
```

On OpenWrt 25.12:

```bash
apk list --installed luci-sso
```

---

## Step 2: Upload the new package

Build or obtain the new `luci-sso` package (see [Building from Source](../../tutorials/building.md)), then copy it to the router:

```bash
# OpenWrt 24.10
scp -O bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/luci-sso_<version>_<arch>.ipk root@192.168.1.1:/tmp/
# OpenWrt 25.12
scp -O bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/luci-sso-<version>.apk root@192.168.1.1:/tmp/
```

If the crypto backend has a new version too, copy that package as well.

---

## Step 3: Install the upgrade

=== "OpenWrt 24.10 (opkg)"

    Install the new file. `opkg install` upgrades a package that is already installed; `opkg upgrade` does not accept a file name.

    ```bash
    opkg install /tmp/luci-sso_<version>_<arch>.ipk
    ```

    `opkg` reports `Upgrading luci-sso on root from <old> to <new>...`. To also upgrade the crypto backend:

    ```bash
    opkg install /tmp/luci-sso-crypto-mbedtls_<version>_<arch>.ipk
    ```

=== "OpenWrt 25.12 (apk)"

    Add the new file. `apk add` replaces the installed version in place; your changed `/etc/config/luci-sso` stays, and so does the crypto backend. Do not `apk del` first: that is a removal, which logs everyone out.

    ```bash
    apk add --allow-untrusted /tmp/luci-sso-<version>.apk
    ```

The install script runs again during the upgrade: it recreates `/var/run/luci-sso/` if needed, keeps the cleanup cron job, re-applies the SSO button to LuCI's login templates (with `luci-sso-repatch`) and clears LuCI's cache. There is nothing to run by hand.

If `/etc/config/luci-sso-opkg` (or `luci-sso.apk-new`) appeared, compare it with your configuration for new options, then delete it.

---

## Step 4: Verify

Confirm the service reports enabled. On the router:

```bash
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
# Expected: {"enabled": true}
```

Then attempt a login from a browser. Check the log if anything goes wrong:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -20
    ```

---

## Roles with only `read '*'`

Older releases treated a `*` in **either** list as full admin. A role that set `list read '*'` without `list write '*'` therefore got full read and write access, plus unrestricted `ubus`, `uci` and `file` access, by mistake. It now gets what the documentation always described: read on every LuCI access group, and nothing more.

If such a role was meant to be a full admin, add the write wildcard:

```bash
uci add_list luci-sso.<role>.write='*'
uci commit luci-sso
```

The shipped `admin` role sets both wildcards and is unaffected.

---

## Leftover secret key from older versions

Older releases created `/etc/luci-sso/secret.key` on the first login. It once signed session tokens that `luci-sso` stopped issuing when sessions moved to `rpcd`; later releases still generated it but never used it. Current versions neither create nor read it, and upgrading leaves it in place. It is safe to delete:

```bash
rm -rf /etc/luci-sso
```

---

## Restore the login button after a LuCI upgrade

The SSO button is added to LuCI's login templates (`sysauth.ut`) when `luci-sso` is installed. Upgrading LuCI replaces those templates and removes the button. Put it back with:

```bash
luci-sso-repatch
```

It patches the generic template and every theme's own copy, and prints one `patched: <file>` line for each. It is safe to run any number of times; each template ends up with exactly one button. Nobody is logged out. Reload the login page to see the button.

It exits with status 1 and prints `not patched (no header include found): <file>` if a template no longer has the line the button is added after, which would mean a LuCI release changed its login template. `luci-sso-repatch --remove` takes the button out again.

---

## Rolling back

To go back to a previous version, install the old package file.

On OpenWrt 24.10:

```bash
scp -O luci-sso_<old-version>_<arch>.ipk root@192.168.1.1:/tmp/
opkg install --force-downgrade /tmp/luci-sso_<old-version>_<arch>.ipk
```

On OpenWrt 25.12, add the old file:

```bash
apk add --allow-untrusted /tmp/luci-sso-<old-version>.apk
```

The install script runs as part of the rollback, your `/etc/config/luci-sso` is kept, and nobody is logged out.
