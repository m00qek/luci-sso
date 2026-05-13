# How to Remove luci-sso

This guide covers completely removing `luci-sso` from your router and restoring the standard LuCI password login.

---

## What happens on removal

Running `opkg remove luci-sso` triggers a pre-removal script that automatically:

- Removes the daily cleanup cron job from `/etc/crontabs/root`.
- Reverts the LuCI login template (`sysauth.ut`) — the SSO button is removed from the login page.
- Clears the LuCI module cache so the change is reflected immediately.

The standard username/password login is restored as soon as the package is removed. Users do not need to reboot.

---

## Step 1: Remove the packages

Remove the main package and its crypto backend:

```bash
opkg remove luci-sso luci-sso-crypto-mbedtls
```

If you installed a different backend, replace `luci-sso-crypto-mbedtls` with the one you used:

```bash
# WolfSSL backend
opkg remove luci-sso luci-sso-crypto-wolfssl

# OpenSSL backend
opkg remove luci-sso luci-sso-crypto-openssl
```

---

## Step 2: Confirm the login page is restored

Open a browser and navigate to `https://<YOUR_ROUTER>/cgi-bin/luci/`. The SSO button should be gone and only the standard username and password fields should be visible.

If the SSO button is still showing, the LuCI cache may not have cleared. Run:

```bash
rm -rf /tmp/luci-modulecache/ /tmp/luci-indexcache
```

Then reload the page.

---

## Step 3: Clean up remaining files (optional)

`opkg remove` does not delete two categories of files: conffiles and files created at runtime.

**Configuration** — `/etc/config/luci-sso` is preserved by opkg's conffile mechanism. Remove it if you do not plan to reinstall:

```bash
rm /etc/config/luci-sso
```

**Session signing key** — `/etc/luci-sso/secret.key` is generated at runtime on first use, so opkg does not track it. Remove the entire directory:

```bash
rm -rf /etc/luci-sso
```

**Runtime state** — `/var/run/luci-sso/` lives on tmpfs and disappears on the next reboot. If you want to clear it immediately:

```bash
rm -rf /var/run/luci-sso
```

**Custom CA certificates** — If you added a private CA certificate for a self-hosted IdP during split-horizon setup, remove it manually:

```bash
rm /etc/ssl/certs/my-homelab-ca.crt
update-ca-certificates
```

---

## What happens to active SSO sessions

Users who are currently logged in via SSO remain logged in until their UBUS session expires. `opkg remove` does not invalidate existing sessions — that would require a UBUS restart, which would also log out any password-authenticated users.

If you need to immediately revoke all active sessions, restart the UBUS session manager:

```bash
/etc/init.d/rpcd restart
```

This logs out all users, including those authenticated with a password.
