# How to Run LuCI Behind a Reverse Proxy

This guide puts LuCI and `luci-sso` behind a reverse proxy that terminates TLS, such as nginx on the router itself. The proxy holds the certificate and serves `https://router.example.com`, and `uhttpd` serves plain HTTP on the loopback interface only.

The examples use nginx. Any reverse proxy works if it does the same things: HTTPS towards the browser, every path passed to `uhttpd`, a read timeout long enough for an `rpcd` reload, and a per-client limit on requests to `/cgi-bin/luci-sso`.

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
- nginx with TLS support installed on the router: `opkg install nginx-ssl` on OpenWrt 24.10, `apk add nginx-ssl` on OpenWrt 25.12.
- A public host name for the router, for example `router.example.com`, that resolves to the router for every browser that will use it.
- A certificate for that host name, and its key, on the router. Browsers must trust it.
- **Console or SSH access to the router.** Once `uhttpd` moves to the loopback interface, LuCI is reachable only through nginx. If nginx does not start, SSH is the way back in.

---

## 1. Write the nginx configuration

Write the server blocks before moving `uhttpd`, so that nginx can take over ports 80 and 443 as soon as `uhttpd` releases them. Put them where your nginx configuration includes them, for example a file in `/etc/nginx/conf.d/`:

```nginx
# Per-client limits for luci-sso, which leaves them to the proxy (step 4).
# The same numbers as luci-sso: 10 login starts per 5 minutes, and 30
# requests a minute.
limit_req_zone $binary_remote_addr zone=luci_sso:1m       rate=30r/m;
limit_req_zone $luci_sso_login     zone=luci_sso_login:1m rate=2r/m;
limit_req_status 429;

# The login page's probe, ?action=enabled, is not a login start. An empty
# key is not counted.
map $args $luci_sso_login {
    ~^action=enabled$  "";
    default            $binary_remote_addr;
}

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

    # For every location below.
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    # Above uhttpd's 30 s stall during an rpcd reload, and long enough
    # for a firmware upgrade or backup.
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;

    location / {
        proxy_pass http://127.0.0.1:8081;
    }

    # A luci-sso login start: /cgi-bin/luci-sso, with or without a final /.
    location ~ ^/cgi-bin/luci-sso/?$ {
        limit_req zone=luci_sso_login burst=9 nodelay;
        limit_req zone=luci_sso burst=29 nodelay;
        proxy_pass http://127.0.0.1:8081;
    }

    # The callback, the logout and every other luci-sso path. No final /:
    # with one, nginx would answer /cgi-bin/luci-sso itself with a redirect,
    # without the limits above.
    location /cgi-bin/luci-sso {
        limit_req zone=luci_sso burst=29 nodelay;
        proxy_pass http://127.0.0.1:8081;
    }
}
```

What matters in the LuCI block:

- **Proxy every path.** `location /` covers everything. If you proxy selected paths instead, include at least `/cgi-bin/luci`, `/cgi-bin/luci-sso`, `/luci-static` (LuCI's scripts, including the SSO button) and `/ubus` (LuCI's calls to `rpcd`), and `/` itself: a logout without RP-Initiated Logout ends at `/`, and the IdP sends the browser back to `https://router.example.com/` after one.
- **`Host`.** `luci-sso` does not read it, so a rewritten `Host` does not break the SSO login or logout. Pass the browser's `Host` anyway, so that `uhttpd` and LuCI see the name the browser used.
- **Timeout.** When `rpcd` reloads, for example after you save roles in **Services > Single Sign-On**, `uhttpd` can wait up to half its script timeout (30 s by default) and answer nothing meanwhile; see [the `luci-sso` ubus object](../../reference/uci-config.md#the-luci-sso-ubus-object). Set `proxy_read_timeout` comfortably above that. The 600 s above also covers firmware upgrades and backups, which take longer.
- **Per-client limits.** The two `limit_req_zone` lines, the `map` and the two `/cgi-bin/luci-sso` locations limit each browser, by its own address, as `luci-sso` would. Once step 4 exempts the proxy, `luci-sso` no longer does, so these limits are the ones that count. [Why nginx limits the clients](#why-nginx-limits-the-clients) explains each setting.
- **Forwarding headers.** `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Real-IP` are harmless to add, but `luci-sso` never sees them: `uhttpd` does not pass them to CGI scripts.

Check the syntax:

```bash
nginx -t
```

nginx refuses two `default_server` blocks on the same port, and `nginx -t` says so. If your configuration already has default servers for ports 80 and 443, as OpenWrt's generated nginx configuration can, keep only one per port.

The `limit_req_zone`, `limit_req_status` and `map` lines belong in nginx's `http` context, outside any `server` block. A file in `/etc/nginx/conf.d/` is read in that context, so they can stay at the top of the file.

### Why nginx limits the clients

`luci-sso` limits each client by its address, which it takes from `REMOTE_ADDR`. Behind the proxy, that is always the proxy's address, `127.0.0.1`. The proxy does know each browser's address, but `uhttpd` passes only a fixed list of request headers to CGI scripts, and `X-Forwarded-For` and `X-Real-IP` are not on it. So `luci-sso` cannot tell the browsers apart. Left as it is, it would count every user as one client, and ten login starts in five minutes, from anyone, would lock everyone else out of SSO for the rest of the window.

So the proxy limits each browser, and `luci-sso` exempts the proxy from its own per-client limits ([step 4](#4-exempt-the-proxy-from-luci-ssos-per-client-limits)). The settings above give each browser the budgets `luci-sso` would:

| `luci-sso` | nginx | Why |
| :--- | :--- | :--- |
| 10 login starts per 5 minutes | `rate=2r/m` and `burst=9` in `luci_sso_login` | 2 a minute is 10 per 5 minutes. `burst=9` lets a browser make its first 10 at once, as `luci-sso` does: the first fits the rate, and 9 more fit the burst. |
| 30 requests a minute | `rate=30r/m` and `burst=29` in `luci_sso` | The same reasoning: 30 at once, then the rate. |
| `429` with `Retry-After` | `limit_req_status 429` | nginx's default is `503`, which `luci-sso` uses for a full handshake table. nginx sends no `Retry-After`. |

- **`nodelay`.** Without it, nginx holds the requests above the rate and releases them one at a time at the rate: a login start could wait more than a minute before the browser is sent to the IdP. With `nodelay`, every request within the burst is served at once, and the next one gets `429` at once, as with `luci-sso`.
- **Refill.** nginx gives a browser's budget back gradually, one login start every 30 s and one request every 2 s. `luci-sso` gives it all back when its fixed window ends. Over time, both allow the same rate.
- **The probe.** The login page asks `/cgi-bin/luci-sso?action=enabled` whether to show the SSO button. The `map` keeps it out of the login-start budget. It does count toward the 30 requests a minute, unlike in `luci-sso`; a login page sends one per load. Only the exact query `action=enabled` is left out: any other spelling counts as a login start, which is the safe side.
- **IPv6.** `luci-sso` counts a whole IPv6 `/64` as one client; `$binary_remote_addr` is the full address. A host with a `/64` can therefore get many budgets from nginx. The global limits in `luci-sso`, such as the 500 logins in progress, still apply; see [Request limits](../../reference/http-api.md#request-limits).

---

## 2. Move uhttpd to the loopback interface

!!! warning "Keep a way back in"
    Run these commands from an SSH session or the serial console, and keep it open until [Verify](#5-verify) passes. From here until nginx runs, LuCI cannot be reached from the network.

Note the current value of `redirect_https`, so you can restore it if you go back:

```bash
uci get uhttpd.main.redirect_https
```

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
uci set uhttpd.main.redirect_https='<the value you noted>'
uci commit uhttpd
service uhttpd restart
```

If `uci get` answered `Entry not found`, run `uci delete uhttpd.main.redirect_https` instead of setting it.

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

## 4. Exempt the proxy from luci-sso's per-client limits

Every request reaches `uhttpd` from `127.0.0.1`, so `luci-sso` counts all users as that one client; see [Why nginx limits the clients](#why-nginx-limits-the-clients). Tell it that this address is the proxy, so that its requests skip `luci-sso`'s per-client limits and only nginx's apply:

=== "Browser (LuCI)"

    Open **Services > Single Sign-On**, the **Advanced** tab. Under **Trusted Proxy**, add `127.0.0.1`, and click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci add_list luci-sso.default.trusted_proxy='127.0.0.1'
    uci commit luci-sso
    ```

Add only the address nginx connects to `uhttpd` from: `127.0.0.1` for the `proxy_pass` above, or `::1` if you proxy to `[::1]`. Any request from that address skips the per-client limits, so it must be an address no other client can send from. `127.0.0.1` is one: only programs on the router can use it. Do not add the router's LAN address or a LAN range. A LAN range is where your users' devices are, so they would skip the limits too, and for nginx to reach `uhttpd` at the router's LAN address, `uhttpd` would have to listen on the LAN, where browsers can reach it directly, past nginx's limits. [Trusted proxies](../../explanation/threat-model.md#trusted-proxies) explains the risk.

The exemption covers only the two per-client limits. The limits that protect the router as a whole, such as the 500 logins in progress, still apply to the proxy's requests.

The first login after this logs, at most once an hour:

```
Request from trusted proxy [id: …] skips the per-client rate limits (trusted_proxy); not logged again for 3600s
```

---

## 5. Verify

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

Check that nginx limits login starts. From a computer on the network, start 11 logins in a row:

```bash
for i in $(seq 11); do
  curl -s -o /dev/null -w '%{http_code}\n' https://router.example.com/cgi-bin/luci-sso
done
# Expected: ten 302, then 429
```

That computer then has to wait 30 s for its next login start. Each `302` left a login in progress on the router, which expires after 5 minutes.

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
| `[429] TOO_MANY_REQUESTS` in the log, preceded by `Login rate limit exceeded` or `Request rate limit exceeded`, and no `Request from trusted proxy` line | `trusted_proxy` is not set, or does not hold the address nginx connects from. Every request reaches `uhttpd` from `127.0.0.1`, so all users share that one client's budget: 10 login starts in 5 minutes, 30 requests a minute | Add the proxy's address to `trusted_proxy`, as in [step 4](#4-exempt-the-proxy-from-luci-ssos-per-client-limits). |
| nginx answers `429 Too Many Requests` to one browser; nothing from `luci-sso` in the log | nginx's per-client limit, as intended: that browser started more than 10 logins in 5 minutes, or sent more than 30 requests to `/cgi-bin/luci-sso` in a minute | Wait 30 s for a login start, 2 s for any other request. |
| The IdP does not send you back after logout | The IdP has no post-logout redirect URI registered for the public host | Register `https://router.example.com/` at the IdP. |

For other failures, see [How to Debug luci-sso](debugging.md) and the [Log Messages Reference](../../reference/log-messages.md).

---

## If the proxy runs on another host

`luci-sso` does not depend on where the proxy runs, but this guide was verified only with the proxy on the router. With the proxy on another host:

- `uhttpd` has to listen on an address that host can reach, and the session cookies then cross that network in plain HTTP between the proxy and the router.
- Every request comes from the proxy's address. Set `trusted_proxy` to that one address, not to `127.0.0.1`, and only if no other client can reach `uhttpd` from it. Every device that can reach `uhttpd` directly bypasses nginx's limits, so let only the proxy's host reach it, with a firewall rule for example.
