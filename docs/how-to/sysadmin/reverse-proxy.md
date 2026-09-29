# How to Run LuCI Behind a Reverse Proxy

This guide puts LuCI and `luci-sso` behind a reverse proxy that terminates TLS, such as nginx on the router itself. The proxy holds the certificate and serves `https://router.example.com`, and `uhttpd` serves plain HTTP on the loopback interface only.

The examples use nginx. Any reverse proxy works if it does the same things: HTTPS towards the browser, every path passed to `uhttpd`, and a read timeout long enough for an `rpcd` reload.

---

## When this works

`luci-sso` does not need to see TLS itself:

- It never checks the scheme of the incoming request. From the CGI environment it reads only `PATH_INFO`, `QUERY_STRING`, `HTTP_COOKIE` and `REMOTE_ADDR`.
- It does not read the `Host` header. Both OIDC legs use the fixed `redirect_uri` from the configuration, and so does the `post_logout_redirect_uri` it sends to the IdP. Every other redirect it issues is a relative path (`/cgi-bin/luci/` or `/`), which the browser resolves against the address it is using.
- Every cookie it sets carries `Secure`, whatever the scheme `uhttpd` sees.
- The **Login with SSO** button runs in the browser. It probes `/cgi-bin/luci-sso?action=enabled` with a relative URL, then sends the browser to `https://` plus the host and port in the address bar, followed by `/cgi-bin/luci-sso`.

So once the browser talks HTTPS to the proxy, the login and logout flows are the same as with `uhttpd` serving HTTPS directly.

This guide covers a proxy **on the router itself**, forwarding over the loopback interface. See [If the proxy runs on another host](#if-the-proxy-runs-on-another-host) for what changes otherwise.

---

## Prerequisites

- `luci-sso` installed; see [How to Install luci-sso](installation.md).
- nginx with TLS support installed on the router (on OpenWrt 25.12, `apk add nginx-ssl`).
- A public host name for the router, for example `router.example.com`, that resolves to the router for every browser that will use it.
- A certificate for that host name, and its key, on the router. Browsers must trust it.
- **Console or SSH access to the router.** Once `uhttpd` moves to the loopback interface, LuCI is reachable only through nginx. If nginx does not start, SSH is the way back in.

---

## 1. Write the nginx configuration

Write the server blocks before moving `uhttpd`, so that nginx can take over ports 80 and 443 as soon as `uhttpd` releases them. Put them where your nginx configuration includes them, for example a file in `/etc/nginx/conf.d/`:

```nginx
# Plain HTTP: send every request to HTTPS.
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

# Unknown host names and bare IP addresses on 443: answer 404.
server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate     /etc/nginx/router.crt;
    ssl_certificate_key /etc/nginx/router.key;
    return 404;
}

# LuCI and luci-sso.
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name router.example.com;
    ssl_certificate     /etc/nginx/router.crt;
    ssl_certificate_key /etc/nginx/router.key;

    # Firmware images uploaded through LuCI are larger than nginx's 1 MB default.
    client_max_body_size 64m;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;

        # Above uhttpd's 30 s stall during an rpcd reload, and long enough
        # for a firmware upgrade or backup.
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
```

What matters in the LuCI block:

- **Proxy every path.** `location /` covers everything. If you proxy selected paths instead, include at least `/cgi-bin/luci`, `/cgi-bin/luci-sso`, `/luci-static` (LuCI's scripts, including the SSO button) and `/ubus` (LuCI's calls to `rpcd`), and `/` itself: a logout without RP-Initiated Logout ends at `/`, and the IdP sends the browser back to `https://router.example.com/` after one.
- **`Host`.** `luci-sso` does not read it, so a rewritten `Host` does not break the SSO login or logout. Pass the browser's `Host` anyway, so that `uhttpd` and LuCI see the name the browser used.
- **Timeout.** When `rpcd` reloads, for example after you save roles in **Services > Single Sign-On**, `uhttpd` can wait up to half its script timeout (30 s by default) and answer nothing meanwhile; see [the `luci-sso` ubus object](../../reference/uci-config.md#the-luci-sso-ubus-object). Set `proxy_read_timeout` comfortably above that. The 600 s above also covers firmware upgrades and backups, which take longer.
- **Forwarding headers.** `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Real-IP` are harmless to add, but `luci-sso` reads none of them.

Check the syntax:

```bash
nginx -t
```

nginx refuses two `default_server` blocks on the same port, and `nginx -t` says so. If your configuration already has default servers for ports 80 and 443, as OpenWrt's generated nginx configuration can, keep only one per port.

---

## 2. Move uhttpd to the loopback interface

!!! warning "Keep a way back in"
    Run these commands from an SSH session or the serial console, and keep it open until [Verify](#4-verify) passes. From here until nginx runs, LuCI cannot be reached from the network.

Make `uhttpd` listen on `127.0.0.1:8081` over plain HTTP only, and stop it redirecting to HTTPS:

```bash
uci delete uhttpd.main.listen_http
uci delete uhttpd.main.listen_https
uci add_list uhttpd.main.listen_http='127.0.0.1:8081'
uci set uhttpd.main.redirect_https='0'
uci commit uhttpd
service uhttpd restart
```

`uci delete` answers `Entry not found` if an option was not set; that is harmless. Then start nginx on the ports `uhttpd` has released:

```bash
service nginx enable
service nginx restart
```

To go back to `uhttpd` serving the network directly:

```bash
service nginx stop
uci delete uhttpd.main.listen_http
uci add_list uhttpd.main.listen_http='0.0.0.0:80'
uci add_list uhttpd.main.listen_http='[::]:80'
uci add_list uhttpd.main.listen_https='0.0.0.0:443'
uci add_list uhttpd.main.listen_https='[::]:443'
uci commit uhttpd
service uhttpd restart
```

---

## 3. Use the public host name in the SSO settings

The browser only ever sees the proxy, so every URL the IdP knows must use the proxy's public host name.

=== "Browser (LuCI)"

    Open LuCI at `https://router.example.com` and navigate to **Services > Single Sign-On**. Set **Redirect URI** to `https://router.example.com/cgi-bin/luci-sso/callback`, and click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.redirect_uri='https://router.example.com/cgi-bin/luci-sso/callback'
    uci commit luci-sso
    ```

At the IdP, register:

| IdP setting | Value |
| :--- | :--- |
| Redirect (callback) URI | `https://router.example.com/cgi-bin/luci-sso/callback`, exactly as in `redirect_uri` |
| Post-logout redirect URI | `https://router.example.com/`, the origin of `redirect_uri` followed by `/` |

Open LuCI at that same host name. The handshake cookie `__Host-luci_sso_state` is `Secure` and host-only: the browser sends it only over HTTPS and only back to the host that received it. A login started at `https://192.168.1.1` or over plain HTTP cannot finish at `https://router.example.com/cgi-bin/luci-sso/callback`. See [Cookies](../../reference/http-api.md#cookies).

---

## 4. Verify

On the router, check that `uhttpd` answers on the loopback interface:

```bash
uclient-fetch -q -O - 'http://127.0.0.1:8081/cgi-bin/luci-sso?action=enabled'
# Expected: {"enabled": true}
```

From a computer on the network, check the same through the proxy:

```bash
curl https://router.example.com/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled": true}
```

`{"enabled": false}` means SSO is turned off. An error page means SSO is on but the configuration was rejected; the log line `Configuration rejected: …` names the option.

Check that `uhttpd` is no longer reachable from the network:

```bash
curl -m 5 http://192.168.1.1:8081/
# Expected: a connection error
```

Then log in: open `https://router.example.com`, click **Login with SSO**, sign in at the IdP, and check that LuCI opens. Log out from LuCI's menu and check that the IdP sends you back to `https://router.example.com/`.

---

## Troubleshooting

Read the log first:

--8<-- "check-log.md"

| What you see | Cause | Fix |
| :--- | :--- | :--- |
| nginx answers `502 Bad Gateway`; nothing from `luci-sso` in the log | nginx cannot reach `uhttpd` | Check that `uhttpd` runs and that `netstat -ltn` lists `127.0.0.1:8081`, the address in `proxy_pass`. |
| nginx answers `504 Gateway Timeout` after saving roles; nothing from `luci-sso` in the log | `proxy_read_timeout` is shorter than the `uhttpd` stall during an `rpcd` reload | Raise `proxy_read_timeout` above 30 s. |
| The IdP shows an invalid or mismatched redirect URI; nothing from `luci-sso` after `Initiating OIDC login flow` | The IdP has no callback registered for the public host name | Register `redirect_uri` at the IdP exactly. |
| `[401] MISSING_HANDSHAKE_COOKIE` | The login started at a different host name than the one in `redirect_uri`, or over plain HTTP | Open LuCI at the host in `redirect_uri`, over HTTPS. |
| `[500] CONFIG_ERROR`, after `Configuration rejected: redirect_uri is mandatory and must use HTTPS` | `redirect_uri` is empty or uses `http://` | Set it to the proxy's `https://` URL. |
| `[429] TOO_MANY_REQUESTS` with several users | Every request reaches `uhttpd` from `127.0.0.1`, so all users share one client's rate-limit budget: 10 login starts in 5 minutes, 30 requests a minute | Wait for the time in `Retry-After`. `X-Forwarded-For` is not trusted; see [Request limits](../../reference/http-api.md#request-limits). |
| The IdP does not send you back after logout | The IdP has no post-logout redirect URI registered for the public host | Register `https://router.example.com/` at the IdP. |

For other failures, see [How to Debug luci-sso](debugging.md) and the [Log Messages Reference](../../reference/log-messages.md).

---

## If the proxy runs on another host

`luci-sso` does not depend on where the proxy runs, but this guide was verified only with the proxy on the router. With the proxy on another host:

- `uhttpd` has to listen on an address that host can reach, and the session cookies then cross that network in plain HTTP between the proxy and the router.
- Every request comes from the proxy's address, so all users still share one rate-limit budget.
