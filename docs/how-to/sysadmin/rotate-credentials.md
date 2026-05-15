# How to Rotate Credentials

This guide covers updating the OIDC client credentials on your router — either because the client secret has expired, been compromised, or because you are migrating to a new client registration or a different identity provider.

---

## How credential changes take effect

`luci-sso` reads UCI configuration on every request. There is no daemon to restart — changes committed with `uci commit` take effect on the next login attempt. Active LuCI sessions are not affected: UBUS sessions do not carry the client secret, so users who are already logged in remain logged in until their session expires naturally.

---

## Rotate the client secret

The most common case: the secret is expired or has been compromised. The client ID stays the same; only the secret changes.

**Step 1.** In your IdP, regenerate or replace the client secret for the existing `luci-sso` client registration. Copy the new secret.

**Step 2.** Update the router:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**. Update **Client Secret** with the new secret, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

**Step 3.** Verify the change is live:

```bash
curl -sk https://localhost/cgi-bin/luci-sso?action=enabled
# Expected: {"enabled": true}
```

Then attempt a fresh login from a browser. If the token exchange succeeds, the new secret is working.

If login fails with `TOKEN_EXCHANGE_FAILED` in the log, the new secret was not accepted by the IdP. Double-check it was copied correctly — it is case-sensitive and may contain special characters that need quoting:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `TOKEN_EXCHANGE`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | grep TOKEN_EXCHANGE
    ```

---

## Rotate both the client ID and secret

If re-registering the client entirely (new application registration in the IdP):

**Step 1.** Register a new OAuth2/OIDC client in your IdP. Set the redirect URI to `https://<YOUR_ROUTER>/cgi-bin/luci-sso/callback`.

**Step 2.** Update the router with both values:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**. Update **Client ID** and **Client Secret**, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.client_id='NEW_CLIENT_ID'
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

**Step 3.** Verify with a fresh login. Active sessions from the old client registration remain valid until they expire.

---

## Switch to a different identity provider

Changing `issuer_url` requires clearing the discovery cache in addition to updating credentials, because the cached JWKS and token endpoint URLs from the old IdP will no longer match.

**Step 1.** Register a new client with the new IdP.

**Step 2.** Update the router configuration:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login**. Update **Issuer URL**, **Client ID**, and **Client Secret**, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci set luci-sso.default.issuer_url='https://new-idp.example.com'
    uci set luci-sso.default.client_id='NEW_CLIENT_ID'
    uci set luci-sso.default.client_secret='NEW_SECRET_HERE'
    uci commit luci-sso
    ```

**Step 3.** Clear the discovery and JWKS cache so the router fetches fresh data from the new IdP:

```bash
rm -f /var/run/luci-sso/*.json
```

**Step 4.** Update any role mappings if email addresses or group names differ between the old and new IdP:

=== "Browser (LuCI)"

    Navigate to **Services > SSO Login** and scroll to the **Users** section. Edit each role and update **Email Addresses** and **Groups** as needed, then click **Save & Apply**.

=== "Terminal (SSH)"

    ```bash
    uci show luci-sso | grep email
    # Review and update as needed
    uci commit luci-sso
    ```

**Step 5.** Verify with a fresh login.

Active sessions issued by the old IdP continue to work until they expire — they are UBUS sessions and the router does not re-validate them against the IdP after creation.

---

## Verify roles still match after rotation

If the new credentials come with a different `scope` (for example, the old client had `groups` scope and the new one does not), users may authenticate successfully but see `USER_NOT_AUTHORIZED` in the log — the line before it will say "matched no roles", indicating the group claims are missing.

Check what the IdP is returning after a successful login:

=== "Browser (LuCI)"

    Navigate to **Status > System Log** and filter for `luci-sso`.

=== "Terminal (SSH)"

    ```bash
    logread -e luci-sso | tail -30
    ```

If you see `USER_NOT_AUTHORIZED` with a "matched no roles" line before it, confirm the `scope` option includes all the scopes your role mappings rely on:

```bash
uci show luci-sso.default.scope
```

See [How to Configure Role-Based Access Control](rbac.md) and the [UCI Configuration Reference](../../reference/uci-config.md) for the full list of options.
