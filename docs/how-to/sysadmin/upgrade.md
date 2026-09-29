# How to Upgrade luci-sso

This guide walks through upgrading an existing `luci-sso` installation to a new version, restoring the SSO button after a LuCI upgrade, and rolling back.

!!! warning "Upgrading from 0.9.1 or earlier: role permissions move to rpcd"
    Releases up to 0.9.1 kept each role's permissions in `/etc/config/luci-sso`. 0.10.0 and later keep them in `/etc/config/rpcd`, and a user gets only the **first** matching role. The upgrade moves the permissions for you, but work through [Before you upgrade from 0.9.1 or earlier](#before-you-upgrade-from-091-or-earlier) first.

!!! warning "Upgrading from 0.9.1 or earlier: email rules need a verified email"
    From 0.10.0, an `email` rule matches only if the IdP marks the address as verified (`email_verified: true`). Keycloak, Authentik and Pocket ID send `false` by default for addresses an administrator entered, and so does Authelia's ID Token under a claims policy that lists `email` alone. Users who match only by email then cannot log in. Deal with it [before you upgrade](#before-you-upgrade-from-091-or-earlier).

!!! note "Sessions and the upgrade"
    Installing a newer or older `luci-sso` package over the installed one normally keeps every LuCI session. The install script reloads `rpcd`, which keeps each session and rebuilds its rights from its login entry. The upgrade from 0.9.1 or earlier is the exception:

    - On OpenWrt 24.10 it logs **every** user out once, `root` included. `opkg` runs the old package's removal script during the upgrade, and the removal script of 0.9.1 and earlier restarts `rpcd`, which ends every session. Upgrade over SSH, not from LuCI's **Software** page.
    - On OpenWrt 25.12, SSO sessions opened before it lose their rights at the reload, and their users log in again. Password sessions are kept.

---

## Before you upgrade from 0.9.1 or earlier

Do these steps in this order. All of them but step 6 work with the release you run now, so they are done before you install. The root password login is never affected: if SSO stops working, you can still log in to LuCI with the password.

1.  **Keep a way back.** Check that the `root` password works, keep the package files of the version you run now (see [Rolling back](#rolling-back)), and have SSH access to the router. On OpenWrt 24.10, do the upgrade over SSH: it logs out every LuCI session, including the one that would run it from the **Software** page.

2.  **Set `issuer_url` to the IdP's exact issuer.** 0.10.0 compares it with the `issuer` in the IdP's discovery document character for character, including a trailing slash; 0.9.1 ignored a trailing slash, letter case in the scheme or host, and `:443`. An exact value works with both. Read the declared issuer from any machine that reaches the IdP:

    ```bash
    curl -s https://auth.example.com/application/o/luci-router/.well-known/openid-configuration | jq -r .issuer
    ```

    Without `jq`, find the `"issuer"` field in the JSON. Then, on the router, set `issuer_url` to that value, exactly:

    ```bash
    uci set luci-sso.default.issuer_url='https://auth.example.com/application/o/luci-router/'
    uci commit luci-sso
    ```

    Authentik's issuer ends with `/`; Keycloak's, Authelia's, Pocket ID's and Google's do not. The table in [Provider Compatibility](../../reference/provider-compatibility.md#issuer-identifiers) gives each format.

3.  **Make email rules work with a verified email.** For each user who matches a role only by `email`, do one of these:

    - make the IdP send `email_verified: true`; the table in [Email rules need a verified email](#email-rules-need-a-verified-email) says how for each IdP;
    - move the user to a `group` rule;
    - or, only if users cannot set their own address at the IdP, turn the check off. 0.9.1 ignores the option, and its settings page does not show it, so set it over SSH:

        ```bash
        uci set luci-sso.default.require_email_verified='0'
        uci commit luci-sso
        ```

4.  **Check that the ID Token has a single audience.** 0.10.0 refuses an ID Token whose `aud` lists any client besides `client_id`. At the IdP, remove any mapper that adds other clients to the ID Token's audience, such as a Keycloak **Audience** mapper with **Add to ID token** on. See [An ID Token with more than one audience is refused](#an-id-token-with-more-than-one-audience-is-refused).

5.  **Register the post-logout redirect URI at the IdP.** In 0.10.0, LuCI's **Log out** sends SSO users to the IdP's `end_session_endpoint`, with `post_logout_redirect_uri` set to the origin of `redirect_uri` followed by `/`, for example `https://router.example.com/`. Keycloak and Authentik show an error page for a URI they do not have registered. Add it to the client's post-logout redirect URIs; see [Provider Compatibility](../../reference/provider-compatibility.md#logout).

6.  **Note the change to `internal_issuer_url`, if you set it.** 0.10.0 accepts only an origin, such as `https://auth.lan:9443`, and adds the issuer's path itself. 0.9.1 appended `/.well-known/openid-configuration` to the value as given, so for an issuer with a path, as Keycloak's and Authentik's have, the value had to include that path. A value with a path turns SSO off in 0.10.0: every login fails with `[500] CONFIG_ERROR`, after `Configuration rejected: internal_issuer_url must be an origin (scheme://host[:port]) with no path, query or fragment`. An origin alone would break discovery on 0.9.1, so when the value has a path, reduce it to its origin right after installing, in the same SSH session:

    ```bash
    uci set luci-sso.default.internal_issuer_url='https://auth.lan:9443'
    uci commit luci-sso
    ```

    See [How to Configure Split-Horizon Networking](split-horizon.md#what-gets-replaced).

7.  **On OpenWrt 25.12, just before you install, end open sessions of a role named like an `rpcd` login.** A role named, for example, `root` gives its 0.9.1 sessions the username `root`, so at the upgrade's reload they would get the `root` login's rights. List the `rpcd` logins, then the sessions:

    ```bash
    uci show rpcd | grep username
    ubus call session list | grep -E '"(ubus_rpc_session|oidc_id_token|username)"' | cut -c1-80
    ```

    A session with an `oidc_id_token` line is an SSO session. Destroy each SSO session whose `username` is the name of an `rpcd` login:

    ```bash
    ubus call session destroy '{"ubus_rpc_session": "<session ID>"}'
    ```

    On OpenWrt 24.10 there is nothing to do: the upgrade logs everyone out.

Then install the upgrade with Step 2 below, and [check the result](#check-the-result).

---

## What persists across an upgrade

| Item | Persists? | Notes |
| :--- | :--- | :--- |
| `/etc/config/luci-sso` | ✅ Yes | Declared as a `conffile`. If you changed it, your version is kept and the new default is saved next to it as `/etc/config/luci-sso-opkg` (`luci-sso.apk-new` on OpenWrt 25.12). |
| Role permissions | ✅ Yes | Each role's rpcd login entry, `luci_sso_<role>` in `/etc/config/rpcd`, is left as it is. An upgrade from 0.9.1 or earlier creates the entries from the roles' old `read` and `write` lists. |
| Active LuCI sessions | ✅ Yes, except from 0.9.1 or earlier | The install script reloads `rpcd`, which keeps every session and rebuilds its rights from its login entry. On OpenWrt 24.10, the upgrade from 0.9.1 or earlier logs everyone out once, `root` included: `opkg` runs the old package's removal script, which restarts `rpcd`. On OpenWrt 25.12, SSO sessions opened before that upgrade lose their rights at the reload. |
| `/var/run/luci-sso/` | ✅ Until reboot | This is a tmpfs directory. Its contents survive the upgrade but are cleared on the next reboot. |
| Token registry entries | ✅ Until reboot | Expired entries are removed by the daily cleanup job, not by the upgrade. |
| SSO button on the login page | ✅ Yes | The install script puts it back with `luci-sso-repatch`. On OpenWrt 24.10 the old package's removal script takes it out first. |
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

## Step 2: Install the upgrade

=== "From the package feed"

    If you installed from the [package feed](installation.md#3-install-from-the-package-feed), let the package manager fetch the new version. The crypto backend is upgraded with it when the feed has a new version.

    On OpenWrt 24.10:

    ```bash
    opkg update
    opkg upgrade luci-sso luci-sso-crypto-mbedtls
    ```

    On OpenWrt 25.12:

    ```bash
    apk update
    apk upgrade luci-sso luci-sso-crypto-mbedtls
    ```

    Replace `luci-sso-crypto-mbedtls` with the backend you installed.

=== "From a local package"

    Build the new version (see [How to Build the Packages from Source](build-from-source.md)) and copy it to the router:

    ```bash
    # OpenWrt 24.10
    scp -O bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/luci-sso_<version>_<arch>.ipk root@192.168.1.1:/tmp/
    # OpenWrt 25.12
    scp -O bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/luci-sso-<version>.apk root@192.168.1.1:/tmp/
    ```

    If the crypto backend has a new version too, copy that package as well.

    On OpenWrt 24.10, install the new file. `opkg install` upgrades a package that is already installed; `opkg upgrade` does not accept a file name.

    ```bash
    opkg install /tmp/luci-sso_<version>_<arch>.ipk
    ```

    `opkg` reports `Upgrading luci-sso on root from <old> to <new>...`. To also upgrade the crypto backend:

    ```bash
    opkg install /tmp/luci-sso-crypto-mbedtls_<version>_<arch>.ipk
    ```

    On OpenWrt 25.12, add the new file. `apk add` replaces the installed version in place; your changed `/etc/config/luci-sso` stays, and so does the crypto backend. Do not `apk del` first: that is a removal, which logs everyone out.

    ```bash
    apk add --allow-untrusted /tmp/luci-sso-<version>.apk
    ```

The install script runs again during the upgrade: it recreates `/var/run/luci-sso/` if needed, keeps the cleanup cron job, moves any role permissions still in `/etc/config/luci-sso` into rpcd login entries, reloads `rpcd`, re-applies the SSO button to LuCI's login templates (with `luci-sso-repatch`) and clears LuCI's cache. There is nothing to run by hand, except, from 0.9.1 or earlier, step 6 of [Before you upgrade](#before-you-upgrade-from-091-or-earlier) and the checks in [Upgrading from 0.9.1 or earlier to 0.10.0](#upgrading-from-091-or-earlier-to-0100).

If `/etc/config/luci-sso-opkg` (or `luci-sso.apk-new`) appeared, compare it with your configuration for new options, then delete it.

---

## Step 3: Verify

Confirm the service reports enabled. On the router:

--8<-- "probe-enabled.md"

Then attempt a login from a browser. Check the log if anything goes wrong:

--8<-- "check-log.md"

---

## Upgrading from 0.9.1 or earlier to 0.10.0

Releases up to 0.9.1 kept a role's permissions as `read` and `write` lists on the role in `/etc/config/luci-sso`. 0.10.0 and later keep them in a login entry in `/etc/config/rpcd`, one per role, which the settings page edits. [About Roles and Permissions](../../explanation/roles-and-permissions.md) explains why.

### What changes

- **The configuration format.** A role in `/etc/config/luci-sso` keeps only its name, `email` and `group`. Its permissions are the entry `luci_sso_<role>` in `/etc/config/rpcd`, with `option username 'sso:<role>'`, the `read` and `write` lists, and never a password. See [UCI Configuration](../../reference/uci-config.md). Leftover `read` or `write` options on a role are ignored, with a warning in the log.
- **The first matching role wins.** A user who matches several roles gets the first one, in the order of `/etc/config/luci-sso` and of the settings page. Earlier releases merged every matching role's rights.
- **`*` has rpcd's meaning.** `*` matches every access group, not only LuCI's. A role with `*` in both lists gets exactly what a `root` password login gets. Earlier, `read '*'` read only LuCI's groups, and `write '*'` added raw grants of its own.
- **Every read list includes `unauthenticated`.** LuCI needs that access group on every page, so it is always stored, and the settings page does not list it.
- **Permissions take effect at Save.** On the settings page, read and write access are written to `rpcd` when you click **Save** (or **Save & Apply**), and are in force about a second later, once `rpcd` has reloaded. Emails, groups and role order still take effect with **Save & Apply**. The role editor shows a note saying so.
- **SSO sessions survive `rpcd` reloads.** Installing a LuCI package that reloads `rpcd` no longer strips SSO users of their rights.
- **An ID Token without `at_hash` is accepted.** OIDC Core makes it optional in the authorization code flow, and `luci-sso` now follows it, so IdPs that never send it, such as Authentik, work. A present `at_hash` is still checked, and a wrong one is refused with `AT_HASH_MISMATCH`. The `MISSING_AT_HASH` code is gone.
- **The ID Token's `sub` must be a non-empty string.** A `sub` that is missing, empty, a number or `null` fails the login with `ID_TOKEN_VERIFICATION_FAILED` and the detail `MISSING_SUB_CLAIM`, as OIDC Core §2 requires.
- **The UserInfo `sub` must match exactly.** When the router fetches UserInfo, the `sub` it returns must equal the ID Token's `sub` exactly, as OIDC Core §5.3.2 requires. Earlier releases ignored differences of case, and ignored a UserInfo response without a `sub`. A `sub` that differs only in case, or is missing, not a string or empty, now fails the login with `IDENTITY_MISMATCH`.
- **`issuer_url` must match the IdP's issuer exactly.** It must equal the `issuer` the IdP declares in its discovery document character for character, as OIDC Discovery §4.3 requires, including a trailing slash. Earlier releases ignored a trailing slash, letter case in the scheme or host, and `:443`. See [Check issuer_url](#check-issuer_url).
- **An ID Token with more than one audience is refused.** Its `aud` must be `client_id` alone, as a string or as a one-entry array. An ID Token that also lists another audience now fails with `AUDIENCE_MISMATCH`, even with `azp` set to `client_id`, because `luci-sso` trusts no other audience (OIDC Core §3.1.3.7). The `MISSING_AZP_CLAIM` code is gone: `azp` is never required, and when present it must be `client_id`. See [An ID Token with more than one audience is refused](#an-id-token-with-more-than-one-audience-is-refused).
- **`internal_issuer_url` is an origin only.** It replaces only the scheme, host and port of each back-channel URL, and a value with a path, query or fragment is rejected with `CONFIG_ERROR`, which turns SSO off: `Configuration rejected: internal_issuer_url must be an origin (scheme://host[:port]) with no path, query or fragment`. Earlier releases appended `/.well-known/openid-configuration` to it, so it had to carry the issuer's path. See [How to Configure Split-Horizon Networking](split-horizon.md#what-gets-replaced).
- **LuCI's Log out ends the IdP session too.** For an SSO session, LuCI's **Log out** entry now goes through `luci-sso`, which sends the browser to the IdP's `end_session_endpoint` with `post_logout_redirect_uri` set to the origin of `redirect_uri` followed by `/`. An IdP that has not registered that URI shows an error page instead of returning to the router. See [Provider Compatibility](../../reference/provider-compatibility.md#logout).
- **An email rule needs a verified email.** The new `require_email_verified` option, on by default, makes an `email` rule match only when the IdP marks the address as verified. See [Email rules need a verified email](#email-rules-need-a-verified-email).
- **Removal keeps the permissions.** Removing the package copies each entry's lists back onto its role, then deletes the entries. Installing again moves them back. See [How to Remove luci-sso](uninstall.md).
- **Internal:** the `luci-sso` ubus object has no `move_role` method. Role order is the order of `/etc/config/luci-sso`, which the settings page changes by drag and drop.

### What the upgrade does

The install script moves each role's permissions, in role order:

| Role before the upgrade | After the upgrade |
| :--- | :--- |
| Has `read` or `write` lists | An entry with those lists, plus `unauthenticated`. The lists are removed from the role. |
| The shipped `admin` role, untouched: only `email 'admin@example.com'`, no other email and no group, and no lists | An entry with `read '*'` and `write '*'` |
| Any other role without lists, including an edited `admin` role | An entry that grants nothing but `unauthenticated`, and a warning in the log |
| A name longer than 32 characters or with characters other than letters, digits and `_`, or a read list that denies `unauthenticated` | No entry. The role keeps its lists, and a warning names it. Its users cannot log in. |

Running the script again changes nothing. SSO sessions opened before the upgrade lose their rights at the `rpcd` reload that follows, and their users log in again; on OpenWrt 24.10 everyone was already logged out by the old package's removal script.

If a role has the same name as an `rpcd` login, such as `root`, its open sessions would instead get that login's rights at the reload. End them just before you upgrade, as step 7 of [Before you upgrade from 0.9.1 or earlier](#before-you-upgrade-from-091-or-earlier) describes. On OpenWrt 24.10 the upgrade logs everyone out first, so this cannot happen there.

### Check the result

1.  Read the warnings. The install script prints them and logs them:

    ```bash
    logread -e luci-sso | grep "role '"
    ```

    Each line names a role and what to do, for example `role 'ops' had no permissions to move: its rpcd login entry grants nothing but 'unauthenticated'; set its permissions on the settings page`.

2.  List the entries the upgrade created:

    ```bash
    ubus call luci-sso list_roles
    ```

3.  Open **Services > Single Sign-On**. A role whose **Read Access** shows "(none): this role grants no access" lets its users log in to an empty LuCI. A role that shows "Not set: edit and save this role, or its users cannot log in" has no entry. Edit each one, set its access, and click **Save**.

4.  Check the order of the roles. If a user matches several, only the first counts. Drag the most privileged or most specific role to the top, then click **Save & Apply**. A user who used to combine two roles needs one role that grants both; see [How to Configure Role-Based Access Control](rbac.md).

5.  If a role had `read '*'`, it can now read every access group, not only LuCI's. If it should stay limited to LuCI, list the LuCI groups it needs instead.

### Check issuer_url

Set `issuer_url` before you upgrade, as step 2 of [Before you upgrade from 0.9.1 or earlier](#before-you-upgrade-from-091-or-earlier) describes; the upgrade does not change it. If it still differs from the IdP's issuer by a trailing slash, letter case or `:443`, logins fail after the upgrade with `[502] OIDC_DISCOVERY_FAILED`. The line before it names both values:

```text
luci-sso[1234]: DISCOVERY_ISSUER_MISMATCH: issuer_url is "https://auth.example.com/application/o/luci-router" but the discovery document declares "https://auth.example.com/application/o/luci-router/"; they differ only in a trailing slash, letter case or default port: set issuer_url to exactly the declared value [id: 3c0b5bbd1e0f8f60]
```

Set `issuer_url` to the declared value, exactly, as in step 2. The next login fetches the discovery document again; there is no cache to clear.

### An ID Token with more than one audience is refused

If the IdP adds other clients to the ID Token's `aud`, every login fails after the upgrade:

```text
luci-sso[1234]: OAuth flow failed [session_id: 8e25f313865ad01a]: ID_TOKEN_VERIFICATION_FAILED ({ "details": "AUDIENCE_MISMATCH", "http_status": 401 })
luci-sso[1234]: [401] ID_TOKEN_VERIFICATION_FAILED
```

At the IdP, remove the mapper that adds the other audiences to the ID Token, such as a Keycloak **Audience** mapper with **Add to ID token** on, or turn its ID Token option off. The next login works; there is nothing to change on the router. [Log Messages](../../reference/log-messages.md#issuer-audience-and-access-token) lists the audience checks.

### Email rules need a verified email

A role's `email` rule now matches only if the IdP sends `email_verified: true` with the address, in the same response. The value must be the JSON boolean `true`; the string `"true"` does not count. Before, any address matched. The check stops users who can set their own address at the IdP from claiming someone else's; [About Roles and Permissions](../../explanation/roles-and-permissions.md#verified-email-addresses) explains it. The option that controls it, `require_email_verified`, is on even though an existing `/etc/config/luci-sso` does not mention it.

A user who matches a role only by email, at an IdP that does not send `true`, can no longer log in. The log shows:

```text
luci-sso[1234]: Ignoring the unverified email of user [sub_id: c775e7b757ede630] for role matching: email_verified is not true (require_email_verified) [session_id: 8e25f313865ad01a]
luci-sso[1234]: User [sub_id: c775e7b757ede630] matched no roles [session_id: 8e25f313865ad01a]
```

Users who match by group are not affected, and neither are open sessions.

| IdP | Sends `true` by default? | Fix |
| :--- | :--- | :--- |
| Google | Yes, for a verified Google account | None |
| Authelia | In UserInfo, yes. In the ID Token only if the claims policy lists `email_verified`. | Add `'email_verified'` to the claims policy's `id_token` list; see [How to Configure Authelia](../providers/authelia.md#map-by-email). |
| Keycloak | No, for users an administrator creates | Turn on **Email verified** on each user; see [How to Configure Keycloak](../providers/keycloak.md#map-by-email). |
| Authentik | No, never (since Authentik 2025.10) | Replace the default `email` scope mapping; see [How to Configure Authentik](../providers/authentik.md#map-by-email). |
| Pocket ID | No, for users an administrator creates | Mark each user's email as verified; see [How to Configure Pocket ID](../providers/pocket-id.md#map-by-email). |

Before you upgrade, make the IdP send `true`: the change is harmless to the release you run now, which ignores the claim. Or move the users to `group` rules.

If neither is possible, turn the check off. The upgrade then keeps the old behaviour:

--8<-- "email-verified-off.md"

With the check off, an email rule matches any address the IdP sends. Do this only if users cannot set their own address at the IdP.

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

To go back to a previous version, install the old package file. The package feed may list only the latest release, so keep the package files of any version you may want to return to.

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

### Rolling back to 0.9.1 or earlier

Releases up to 0.9.1 read permissions from the roles, not from `rpcd`, and a downgrade does not run the removal script that puts them back. Remove the package first, then install the old one:

On OpenWrt 24.10:

```bash
opkg remove luci-sso
opkg install /tmp/luci-sso_<old-version>_<arch>.ipk
```

On OpenWrt 25.12:

```bash
apk del luci-sso
apk add --allow-untrusted /tmp/luci-sso-<old-version>.apk
```

The removal copies each role's permissions back onto the role, `unauthenticated` included, and deletes the `luci_sso_*` entries. SSO users lose their rights at the removal and log in again. The old release then merges matching roles and gives `*` its old meaning.
