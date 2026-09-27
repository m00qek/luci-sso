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

A failed request ends with one line holding the HTTP status and an error code:

```
luci-sso[<pid>]: [<http-status>] <CODE>
```

The lines just before it, with the same process ID, usually name the cause. Many specific codes only appear inside those lines, never as `[<status>] <CODE>`. The [Log Messages Reference](../../reference/log-messages.md) says, for every code, where to find it.

---

## The SSO button does not appear

Check that the service is enabled and responding. On the router:

```bash
uclient-fetch -q -O - --no-check-certificate 'https://127.0.0.1/cgi-bin/luci-sso?action=enabled'
```

`--no-check-certificate` is only there because LuCI's certificate is not issued for `127.0.0.1`.

- If it returns `{"enabled": false}`: SSO is disabled. Enable it in **Services > Single Sign-On** (toggle **Enable SSO** on and click **Save & Apply**), or via SSH: `uci set luci-sso.default.enabled='1' && uci commit luci-sso`.
- If the request fails entirely: run the CGI script directly with `QUERY_STRING="action=enabled" /www/cgi-bin/luci-sso`. If the script is missing, check that the package is installed: `opkg list-installed | grep luci-sso` (OpenWrt 24.10) or `apk list --installed | grep luci-sso` (OpenWrt 25.12).
- If it returns an error page and the log shows `CONFIG_ERROR`: a required option is missing or malformed. The line just before it says which one:

    ```
    luci-sso[1234]: Configuration rejected: clock_tolerance must be between 0 and 3600 seconds
    luci-sso[1234]: [500] CONFIG_ERROR
    ```

    The message names the option, never its value. Fix that option in **Services > Single Sign-On** or with `uci set`, then check the rest against the [UCI Configuration Reference](../../reference/uci-config.md).

If the probe returns `{"enabled": true}` but the button is still missing, clear the browser cache and reload the login page. After a LuCI upgrade, restore the button as described in [How to Upgrade luci-sso](upgrade.md#restore-the-login-button-after-a-luci-upgrade).

---

## Clicking the button shows an error page

The router could not start the login, so the browser never reached the IdP.

- **Log shows `[500] OIDC_DISCOVERY_FAILED`**: the router could not use the IdP's discovery document. The line before it names the cause:
    - `Discovery issuer mismatch: Requested [id: …], got [id: …]`: `issuer_url` is not the issuer the IdP declares. Fetch the document from the router and compare its `issuer` with your setting; they must match apart from a trailing slash:

        ```bash
        uclient-fetch -q -O - '<issuer_url>/.well-known/openid-configuration' | jsonfilter -e '@.issuer'
        uci get luci-sso.default.issuer_url
        ```

    - `Discovery fetch failed for [id: …]: HTTP_REQUEST_FAILED (<cause>)`: the router could not connect. See [A back-channel request to the IdP failed](#a-back-channel-request-to-the-idp-failed).
    - `Discovery fetch HTTP <status> from [id: …]`: the IdP answered with an error, usually `404` for a wrong path in `issuer_url`.
    - `Discovery successful for [id: …]` directly before the error: the document lacks a required endpoint, or advertises one over plain HTTP. Check the document's `authorization_endpoint`, `token_endpoint` and `jwks_uri`.
- **Log shows `[429] TOO_MANY_REQUESTS`**: this client started more than 10 logins in 5 minutes, or sent more than 30 requests in a minute. Wait for the time in the `Retry-After` header, or a few minutes.
- **Log shows `[503] HANDSHAKE_CAPACITY_EXCEEDED`**: 500 logins are already in progress. Pending logins expire after 5 minutes. Password login still works meanwhile.

---

## The login fails after returning from the IdP

The browser reached the IdP and came back, but the callback failed. Nothing retries a failed callback: the user starts again from the login page.

- **Log shows `[401] MISSING_HANDSHAKE_COOKIE`**: the browser did not send the handshake cookie. Two common causes:
    - The login page was opened at a different host name than the one in `redirect_uri`, for example `https://192.168.1.1/` while `redirect_uri` is `https://router.lan/…`. The button starts the login at the address in the browser, and the `__Host-` handshake cookie is only sent back to that exact host. Open LuCI at the host in `redirect_uri`, or set `redirect_uri` to the host you use.
    - More than 5 minutes passed between clicking the button and returning from the IdP. The cookie expires after 300 seconds.
- **Log shows `[403] STATE_PARAMETER_MISMATCH`**: the callback does not belong to the login this browser started, for example an old callback URL from the history, or a second login in another tab. The pending login is kept; start again from the login page.
- **Log shows `[401] STATE_NOT_FOUND`**: the callback was already used (a double submit or a reload of the callback URL), or the handshake was cleaned up as stale.
- **Log shows `[401] HANDSHAKE_EXPIRED` or `[401] HANDSHAKE_NOT_YET_VALID`**: the router's own clock jumped during the login. The handshake is written and checked with the router's clock only, so the browser's clock does not matter. See [The router's clock is wrong](#the-routers-clock-is-wrong).
- **Log shows `[400] IDP_ERROR`**: the IdP refused the request. Its reason is not logged; it is in the `error` and `error_description` parameters of the callback URL in the browser's address bar.
- **Log shows `[400] OIDC_INVALID_GRANT` or `TOKEN_EXCHANGE_FAILED`**: the IdP rejected the code exchange. Check the client secret, that the client is confidential, and that `redirect_uri` matches the IdP registration exactly.
- **Log shows `[401] ID_TOKEN_VERIFICATION_FAILED`**: the `OAuth flow failed` line before it names the failed check, such as `TOKEN_EXPIRED` or `UNSUPPORTED_ALGORITHM`. See [ID Token Verification Detail Codes](../../reference/log-messages.md#id-token-verification-detail-codes).

---

## A back-channel request to the IdP failed

When the router cannot complete a request to the IdP (discovery, JWKS, token exchange or UserInfo), the log names the cause in parentheses:

```
luci-sso[1234]: Discovery fetch failed for [id: 957cfa182d5cc6db]: HTTP_REQUEST_FAILED (CERT_UNTRUSTED)
```

The same form appears in `JWKS fetch failed`, `Token exchange network error` and `UserInfo fetch network error` lines.

| Cause | What happened | What to do |
| :--- | :--- | :--- |
| `CONNECT_NOT_STARTED` | The connection could not even start: the host name did not resolve, or there is no route to it. | Check DNS on the router (`nslookup <idp-host>`) and its routes. If the router must reach the IdP at a different address, see [Split-Horizon Networking](split-horizon.md). |
| `CONNECTION_FAILED` | The IdP host refused the connection. | Check that the IdP is running and listening on that port, and that no firewall rejects the router. |
| `TIMED_OUT` | The IdP did not answer within 10 seconds. | Check firewall rules that silently drop traffic, and the IdP's load. |
| `CERT_UNTRUSTED` | The IdP's certificate is not signed by a CA the router trusts. | For a public CA, install `ca-bundle`. For a private CA, follow [How to Install a Private CA Certificate](install-ca-certificate.md). |
| `CERT_NAME_MISMATCH` | The certificate is valid but does not cover the host name the router connected to. | Make `issuer_url` (or `internal_issuer_url`) use a host name listed in the certificate, not an IP address or a different alias. |
| `SSL_INIT_FAILED` | TLS could not be set up at all, before connecting. | The TLS library or the CA store is missing. Check that a `libustream-*` package and `ca-bundle` are installed. |
| `RESPONSE_TOO_LARGE` | The IdP's response exceeded 256 KB. | The URL probably points at the wrong resource. Check `issuer_url`. |
| `UCLIENT_ERROR_<n>` | A transport failure `luci-sso` does not name. | Fetch the same URL from the router with `uclient-fetch -O /dev/null '<url>'`, which prints the error in words. |

---

## Authentication succeeds but the user is denied

The log shows `[403] USER_NOT_AUTHORIZED`, preceded by:

```
luci-sso[1234]: User [sub_id: c775e7b757ede630] matched no roles [session_id: 8e25f313865ad01a]
```

The same line covers two cases:

- The user's email and groups match no `config role` section. Run `uci show luci-sso` and check that the user's exact email or group name appears in a role. Email matching is case-insensitive; group matching is case-sensitive. For Pocket ID, the `@PocketID` suffix is required.
- A role matches, but no matching role has any `read` or `write` entry. Add at least one permission to the role.

Claim values are never logged. To see which claims the IdP sent, look for the debug line logged during the callback:

```
luci-sso[1234]: ID Token verified. Claims present: sub, name, email, email_verified, iat, exp, aud, iss, nonce, at_hash
```

If `email` or `groups` is missing from that list, fix the scopes on the router (`scope`) and the claim mappings at the IdP. To see the values themselves, use the IdP's own tools, such as its user page or token preview.

---

## The router's clock is wrong

`luci-sso` checks the ID Token's `exp`, `nbf` and `iat`, and the handshake's own timestamps, against the router's clock. A wrong or jumping clock shows up as `HANDSHAKE_EXPIRED` or `HANDSHAKE_NOT_YET_VALID`, or as `ID_TOKEN_VERIFICATION_FAILED` with `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID` or `TOKEN_ISSUED_IN_FUTURE` in the `OAuth flow failed` line.

Check the router's current time:

```bash
date
```

OpenWrt keeps time with its built-in NTP client, `sysntpd`.

=== "Browser (LuCI)"

    Navigate to **System > System**, open the **Time Synchronization** tab, enable the NTP client, and click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    # Check the NTP client settings
    uci show system.ntp

    # Make sure it is enabled and running
    uci set system.ntp.enabled='1'
    uci commit system
    /etc/init.d/sysntpd enable
    /etc/init.d/sysntpd restart

    # Or force a one-shot sync and check the result
    ntpd -n -q -p pool.ntp.org && date
    ```

Routers without a hardware clock start with a wrong time and jump when NTP first syncs after boot. A login in progress at that moment fails; the next one works. If clock drift is a recurring problem, increase `clock_tolerance`:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**. Set **Clock Tolerance** to `120`, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.clock_tolerance='120'
    uci commit luci-sso
    ```

The valid range is `0`–`3600` seconds.

---

## Login succeeds but the session has no access

The log shows `[500] UBUS_LOGIN_FAILED`, preceded by a line such as `UBUS session creation failed` or `Failed to load LuCI ACLs for role`.

- Verify `rpcd` is running: `ps | grep rpcd`. If it is not, start it: `/etc/init.d/rpcd start`.
- Verify LuCI ACL files are present: `ls /usr/share/rpcd/acl.d/`. Missing files indicate an incomplete LuCI installation.

---

## Security note

When sharing logs for troubleshooting, redact tokens and internal IP addresses before posting them publicly.
