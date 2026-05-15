# How to Debug luci-sso

This guide describes how to diagnose and resolve authentication failures in `luci-sso`. Each section maps a visible symptom to the likely cause and the steps to fix it.

---

## Read the system log first

All authentication events are written to syslog. Check this before anything else.

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -30
    ```

Each entry follows this format:

```
luci-sso[<pid>]: [<http-status>] <CODE>
```

For every error code and its trigger, see the [Log Messages Reference](../../reference/log-messages.md).

---

## The SSO button does not appear

Check that the service is enabled and responding:

```bash
curl -sk https://192.168.1.1/cgi-bin/luci-sso?action=enabled
```

- If it returns `{"enabled":false}`: SSO is disabled. Enable it in **Services > SSO Login** (toggle **Enable SSO** on and click **Save & Apply**), or via SSH: `uci set luci-sso.default.enabled='1' && uci commit luci-sso`.
- If the request fails entirely: the CGI script is not running. Verify the package is installed: `opkg list-installed | grep luci-sso`.
- If the log shows `CONFIG_ERROR`: a required option is missing or malformed. Run `uci show luci-sso` and check every option against the [UCI Configuration Reference](../../reference/uci-config.md).

---

## The browser redirects to the IdP but the login never completes

The router sent the user to the IdP but the callback back to the router failed.

- **Log shows `OIDC_DISCOVERY_FAILED`**: the router cannot reach `issuer_url`. Test connectivity from the router: `curl -s <issuer_url>/.well-known/openid-configuration`. Check DNS resolution and firewall rules. If the router must reach the IdP at a different internal address, see [How to Configure Split-Horizon Networking](split-horizon.md).
- **Log shows `SSL_INIT_FAILED`**: the router does not trust the IdP's TLS certificate. Install the system CA bundle (`opkg install ca-bundle`) or add your private CA certificate to `/etc/ssl/certs/` and run `update-ca-certificates`.
- **Log shows `STATE_PARAMETER_MISMATCH`**: the browser's handshake cookie was lost, or the user completed the flow in a second tab. This is normal; the user can retry.
- **Log shows `HANDSHAKE_EXPIRED`**: the user took more than five minutes to complete the IdP login. The browser will restart the flow automatically on the next attempt.

---

## Authentication succeeds but the user is denied

The log will show `USER_NOT_AUTHORIZED`. The line immediately before it identifies the cause.

- **"matched no roles"**: the user's email and groups match no `config role` section. Run `uci show luci-sso` and verify the user's exact email or group name appears in a role. Email matching is case-insensitive; group matching is case-sensitive. For Pocket ID, the `@PocketID` suffix is required.
- **"role has no permissions"**: a matching role exists but has no `read` or `write` entries. Add at least one permission to the role.

To see the exact claim values the IdP is sending, check the log lines preceding `USER_NOT_AUTHORIZED` — they include the matched email and groups.

---

## The callback fails with HANDSHAKE_NOT_YET_VALID

The router's clock is ahead of the browser's by more than `clock_tolerance`. The handshake state cookie contains an `iat` timestamp that the router considers to be in the future.

Check the router's current time:

```bash
date
```

If the time is wrong, synchronize it with NTP:

```bash
# Check whether ntpd is running
ps | grep ntpd

# Start it if it is not
service ntp start

# Or force a one-shot sync and check the result
ntpd -n -q -p pool.ntp.org && date
```

If the router has no NTP client installed, install one:

```bash
opkg update && opkg install ntp
service ntp enable
service ntp start
```

After synchronization, try logging in again. If clock drift is a recurring problem on this hardware (common on devices without a hardware real-time clock), increase `clock_tolerance` to accommodate it:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**. Set **Clock Tolerance** to `120`, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.clock_tolerance='120'
    uci commit luci-sso
    ```

The valid range is `0`–`3600` seconds.

---

## Login succeeds but the session has no access

The log will show `UBUS_LOGIN_FAILED` or `UBUS_SESSION_FAILED`.

- Verify `rpcd` is running: `ps | grep rpcd`. If it is not, start it: `service rpcd start`.
- Verify LuCI ACL files are present: `ls /usr/share/rpcd/acl.d/`. Missing files indicate an incomplete LuCI installation.

---

## Security note

When sharing logs for troubleshooting, redact tokens and internal IP addresses before posting them publicly.
