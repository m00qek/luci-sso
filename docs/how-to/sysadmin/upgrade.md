# How to Upgrade luci-sso

This guide walks through upgrading an existing `luci-sso` installation to a new version. The process is safe to perform on a live router — active sessions survive the upgrade and users are not logged out.

---

## What persists across an upgrade

| Item | Persists? | Notes |
| :--- | :--- | :--- |
| `/etc/config/luci-sso` | ✅ Yes | Declared as a `conffile`. `opkg` preserves it. |
| Active LuCI sessions | ✅ Yes | UBUS sessions are in memory; `opkg` does not restart UBUS. |
| `/var/run/luci-sso/` | ✅ Until reboot | This is a tmpfs directory. Its contents survive `opkg upgrade` but are cleared on next reboot. |
| Token registry entries | ✅ Until reboot | Expired tokens are reaped by the cleanup cron job, not by the upgrade. |
| LuCI cache | ❌ Cleared | The post-install script runs `rm -rf /tmp/luci-modulecache/` to force LuCI to reload. |

---

## Step 1: Check the current version

```bash
opkg info luci-sso
```

Look at the `Version:` field in the output.

---

## Step 2: Upload the new package

Build or obtain the new `.ipk`, then copy it to the router:

```bash
scp -O bin/lib/<ARCH>/packages/luci-sso*.ipk root@192.168.1.1:/tmp/
```

If upgrading the crypto backend as well (e.g., switching from MbedTLS to WolfSSL), copy that `.ipk` too.

---

## Step 3: Install the upgrade

Use `opkg upgrade` if `luci-sso` is already installed — this preserves the conffile:

```bash
opkg upgrade /tmp/luci-sso*.ipk
```

If the router modified `/etc/config/luci-sso` after the original installation, `opkg` may prompt you to keep your version or overwrite it with the package default. **Always keep your version** — it contains your IdP credentials and role configuration.

To also upgrade the crypto backend:

```bash
opkg upgrade /tmp/luci-sso-crypto-mbedtls*.ipk
```

---

## Step 4: Apply post-install setup

The package includes two `uci-defaults` scripts that run automatically on first boot after an upgrade. If you are not rebooting the router, run them manually:

```bash
sh /etc/uci-defaults/10-luci-sso-setup
sh /etc/uci-defaults/99-luci-sso-ui
```

`10-luci-sso-setup` ensures the `/var/run/luci-sso` directory exists with correct permissions and registers the cleanup cron job if it is not already present.

`99-luci-sso-ui` re-applies the LuCI login page patch to inject the SSO button. This is necessary whenever LuCI itself is also upgraded, as a LuCI upgrade may overwrite the patched template.

---

## Step 5: Verify

Confirm the service reports enabled:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled": true}
```

Then attempt a login from a browser. Check the log if anything goes wrong:

```bash
logread -e luci-sso | tail -20
```

---

## Upgrading LuCI at the same time

If you upgrade LuCI alongside `luci-sso`, the LuCI upgrade will overwrite `sysauth.ut` and remove the SSO login button. Run the UI setup script after the LuCI upgrade completes:

```bash
sh /etc/uci-defaults/99-luci-sso-ui
```

If the button does not appear on the login page after this, clear the LuCI cache manually:

```bash
rm -rf /tmp/luci-modulecache/ /tmp/luci-indexcache
```

Then reload the page.

---

## Rolling back

To revert to a previous version, install the old `.ipk` with `opkg install --force-reinstall`:

```bash
scp -O luci-sso-<old-version>.ipk root@192.168.1.1:/tmp/
opkg install --force-reinstall /tmp/luci-sso-<old-version>.ipk
sh /etc/uci-defaults/10-luci-sso-setup
sh /etc/uci-defaults/99-luci-sso-ui
```

Your `/etc/config/luci-sso` is not touched by a rollback.
