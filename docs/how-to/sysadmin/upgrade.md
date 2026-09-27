# How to Upgrade luci-sso

This guide walks through upgrading an existing `luci-sso` installation to a new version, restoring the SSO button after a LuCI upgrade, and rolling back.

!!! warning "Upgrading from 0.9.1 or earlier: role permissions move to rpcd"
    Releases up to 0.9.1 kept each role's permissions in `/etc/config/luci-sso`. Later releases keep them in `/etc/config/rpcd`, and a user gets only the **first** matching role. The upgrade moves the permissions for you, but read [Upgrading from 0.9.1 or earlier](#upgrading-from-091-or-earlier) before you start.

!!! note "Sessions survive an upgrade"
    Installing a newer or older `luci-sso` package over the installed one keeps every LuCI session. The install script reloads `rpcd`, which keeps each session and rebuilds its rights from its login entry. The one exception is the upgrade from 0.9.1 or earlier: SSO sessions opened before it lose their rights at that reload, and their users log in again.

---

## What persists across an upgrade

| Item | Persists? | Notes |
| :--- | :--- | :--- |
| `/etc/config/luci-sso` | ✅ Yes | Declared as a `conffile`. If you changed it, your version is kept and the new default is saved next to it as `/etc/config/luci-sso-opkg` (`luci-sso.apk-new` on OpenWrt 25.12). |
| Role permissions | ✅ Yes | Each role's rpcd login entry, `luci_sso_<role>` in `/etc/config/rpcd`, is left as it is. An upgrade from 0.9.1 or earlier creates the entries from the roles' old `read` and `write` lists. |
| Active LuCI sessions | ✅ Yes | The install script reloads `rpcd`, which keeps every session and rebuilds its rights from its login entry. SSO sessions opened before an upgrade from 0.9.1 or earlier lose their rights at that reload. On OpenWrt 24.10, upgrading *from* a release whose removal script restarts `rpcd` also logs everyone out once, because opkg runs the old release's removal script. |
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

The install script runs again during the upgrade: it recreates `/var/run/luci-sso/` if needed, keeps the cleanup cron job, moves any role permissions still in `/etc/config/luci-sso` into rpcd login entries, reloads `rpcd`, re-applies the SSO button to LuCI's login templates (with `luci-sso-repatch`) and clears LuCI's cache. There is nothing to run by hand, except the checks in [Upgrading from 0.9.1 or earlier](#upgrading-from-091-or-earlier) when they apply.

If `/etc/config/luci-sso-opkg` (or `luci-sso.apk-new`) appeared, compare it with your configuration for new options, then delete it.

---

## Step 3: Verify

Confirm the service reports enabled. On the router:

--8<-- "probe-enabled.md"

Then attempt a login from a browser. Check the log if anything goes wrong:

--8<-- "check-log.md"

---

## Upgrading from 0.9.1 or earlier

Releases up to 0.9.1 kept a role's permissions as `read` and `write` lists on the role in `/etc/config/luci-sso`. Later releases keep them in a login entry in `/etc/config/rpcd`, one per role, which the settings page edits. [About Roles and Permissions](../../explanation/roles-and-permissions.md) explains why.

### What changes

- **The configuration format.** A role in `/etc/config/luci-sso` keeps only its name, `email` and `group`. Its permissions are the entry `luci_sso_<role>` in `/etc/config/rpcd`, with `option username 'sso:<role>'`, the `read` and `write` lists, and never a password. See [UCI Configuration](../../reference/uci-config.md). Leftover `read` or `write` options on a role are ignored, with a warning in the log.
- **The first matching role wins.** A user who matches several roles gets the first one, in the order of `/etc/config/luci-sso` and of the settings page. Earlier releases merged every matching role's rights.
- **`*` has rpcd's meaning.** `*` matches every access group, not only LuCI's. A role with `*` in both lists gets exactly what a `root` password login gets. Earlier, `read '*'` read only LuCI's groups, and `write '*'` added raw grants of its own.
- **Every read list includes `unauthenticated`.** LuCI needs that access group on every page, so it is always stored, and the settings page does not list it.
- **Permissions take effect at Save.** On the settings page, read and write access are written to `rpcd` when you click **Save** (or **Save & Apply**), and are in force about a second later, once `rpcd` has reloaded. Emails, groups and role order still take effect with **Save & Apply**. The role editor shows a note saying so.
- **SSO sessions survive `rpcd` reloads.** Installing a LuCI package that reloads `rpcd` no longer strips SSO users of their rights.
- **An ID Token without `at_hash` is accepted.** OIDC Core makes it optional in the authorization code flow, and `luci-sso` now follows it, so IdPs that never send it, such as Authentik, work. A present `at_hash` is still checked, and a wrong one is refused with `AT_HASH_MISMATCH`. The `MISSING_AT_HASH` code is gone.
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

Running the script again changes nothing. SSO sessions opened before the upgrade lose their rights at the `rpcd` reload that follows; their users log in again.

If a role has the same name as an `rpcd` login, such as `root`, its open sessions would instead get that login's rights at the reload. End them before you upgrade, as described in [How to Configure Role-Based Access Control](rbac.md#change-access-for-users-already-logged-in).

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
