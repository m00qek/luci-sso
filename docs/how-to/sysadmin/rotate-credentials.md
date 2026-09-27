# How to Rotate Credentials

This guide covers updating the OIDC client credentials on your router — either because the client secret has expired, been compromised, or because you are migrating to a new client registration or a different identity provider.

!!! warning "Secret storage"
    The client secret is stored in plain text in `/etc/config/luci-sso`. The package installs that file with mode `0644`, so every local user and process can read it, as can anyone with root shell or physical access. To limit it to root, run `chmod 600 /etc/config/luci-sso`; `uci commit` keeps that mode. Do not store this file in version control or share it in support tickets.

---

## How credential changes take effect

`luci-sso` reads UCI configuration on every request. There is no daemon to restart — changes committed with `uci commit` take effect on the next login attempt. Active LuCI sessions are not affected: UBUS sessions do not carry the client secret, so users who are already logged in stay logged in until they log out or their session times out after a period of inactivity.

A leaked client secret does not by itself let anyone into the router: they would still need to sign in at the IdP with an account that matches one of your roles. If you also want to end existing sessions, see [End a user's sessions now](rbac.md#change-access-for-users-already-logged-in).

---

## Rotate the client secret

The most common case: the secret is expired or has been compromised. The client ID stays the same; only the secret changes.

**Step 1.** In your IdP, regenerate or replace the client secret for the existing `luci-sso` client registration. Copy the new secret.

**Step 2.** Update the router:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**. Update **Client Secret** with the new secret, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

**Step 3.** Verify the configuration is still valid. On the router:

--8<-- "probe-enabled.md"

Then attempt a fresh login from a browser. If the token exchange succeeds, the new secret is working.

If the IdP rejects the new secret, the login fails with `502 Bad Gateway` and the log shows lines like these. The first one has the status the IdP returned (usually `401`):

```
Token exchange HTTP 401 [session_id: …]
OAuth flow failed [session_id: …]: TOKEN_EXCHANGE_FAILED ({ "http_status": 502 })
[502] TOKEN_EXCHANGE_FAILED
```

The IdP's own error code (typically `invalid_client`) is not logged. Double-check the secret was copied correctly — it is case-sensitive and may contain special characters that need quoting:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `TOKEN_EXCHANGE`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | grep TOKEN_EXCHANGE
    ```

---

## Rotate both the client ID and secret

If re-registering the client entirely (new application registration in the IdP):

**Step 1.** Register a new OAuth2/OIDC client in your IdP. Its redirect URI must exactly match the router's configured **Redirect URI**; copy it from **Services > Single Sign-On**, or print it with `uci get luci-sso.default.redirect_uri`.

**Step 2.** Update the router with both values:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**. Update **Client ID** and **Client Secret**, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.client_id='NEW_CLIENT_ID'
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

**Step 3.** Verify with a fresh login. Active sessions from the old client registration stay valid until they log out or time out.

A login that was already under way when you saved the change returns from the IdP with a code issued to the old client, so its token exchange fails. Starting the login again works.

---

## Switch to a different identity provider

Changing `issuer_url` needs no cache clearing: the discovery and JWK Set caches in `/var/run/luci-sso/` are keyed by the issuer and `jwks_uri` URLs, so the new IdP's documents are fetched on the first login. Do not delete `/var/run/luci-sso/*.json`: that directory also holds logins in progress and the rate-limit state.

**Step 1.** Register a new client with the new IdP. Its redirect URI must exactly match the router's configured **Redirect URI** (`uci get luci-sso.default.redirect_uri`).

**Step 2.** Update the router configuration:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On**. Update **Issuer URL**, **Client ID**, and **Client Secret**, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://new-idp.example.com'
    uci set luci-sso.default.client_id='NEW_CLIENT_ID'
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

If you use [split-horizon networking](split-horizon.md), `internal_issuer_url` still points at the old IdP's internal address, and discovery for the new IdP will fail with `OIDC_DISCOVERY_FAILED`. Set it to the new IdP's internal origin, or remove it if the router can reach the new IdP directly:

```bash
uci set luci-sso.default.internal_issuer_url='https://10.0.0.5:8443'
# or
uci delete luci-sso.default.internal_issuer_url
uci commit luci-sso
```

In the browser, the same field is **Internal Issuer URL** on **Services > Single Sign-On**.

**Step 3.** Update any role mappings if email addresses or group names differ between the old and new IdP:

=== "Browser (LuCI)"

    Navigate to **Services > Single Sign-On** and scroll to the **Users** section. Edit each role and update **Email Addresses** and **Groups** as needed, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci show luci-sso | grep email
    # Review and update as needed
    uci commit luci-sso
    ```

**Step 4.** Verify with a fresh login. A login that was already under way when you saved the change will fail once; start it again.

Active sessions issued by the old IdP keep working until they log out or time out — they are UBUS sessions and the router does not re-validate them against the IdP after creation.

---

## Verify roles still match after rotation

A new client registration, or a new IdP, may not release the same claims as the old one. For example, the old client was allowed the `groups` scope or had a groups mapper, and the new one does not. Users then authenticate successfully but are refused: the log shows `USER_NOT_AUTHORIZED`, and the line before it says "matched no roles".

Check which claims the IdP sent. After each login, `luci-sso` logs a debug-level line listing the claim names, not their values. For example:

```
ID Token verified. Claims present: iss, sub, aud, exp, iat, nonce, at_hash, email
```

If `groups` (or `email`) is missing there, fix it at the IdP: allow the scope for the new client, or add the claim mapper. To see the line:

--8<-- "check-log.md"

Also confirm the router still requests the scopes your role mappings rely on. `scope` is a router option, not part of the client registration:

```bash
uci show luci-sso.default.scope
```

See [How to Configure Role-Based Access Control](rbac.md) and the [UCI Configuration Reference](../../reference/uci-config.md) for the full list of options.
