# Changelog

All notable changes to `luci-sso` are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Until 1.0, a minor version may change the configuration or behaviour; each such change is listed under **Upgrade actions**.

## [Unreleased]

### Added

- A role can match users by their OIDC `sub` claim, the account identifier that never changes, with `list sub '<value>'` next to `email` and `group`, or the **Subjects (sub)** field of the role editor. The value is compared exactly, letter case included; the issuer is always `issuer_url`. A user who matches no role sees their own `sub` on the error page, to give to the administrator; the log still records only its hash. See [Match one account by its subject](https://m00qek.github.io/luci-sso/latest/how-to/sysadmin/rbac/#match-one-account-by-its-subject).

### Changed

- The documentation has one version per minor release, at `https://m00qek.github.io/luci-sso/<X.Y>/`, starting with 0.9 and 0.10. [`/latest/`](https://m00qek.github.io/luci-sso/latest/) shows the newest release, and a selector on every page switches between versions. Links to the old unversioned pages lead to the same page, and anchor, under `/latest/`.
- The settings page links to the documentation of the installed release, `/0.10/`, instead of the unversioned site.

## [0.10.0] - 2026-09-29

### Upgrade actions

Upgrading from 0.9.1 needs some steps **before** you install, and one right after. Follow [Before you upgrade from 0.9.1 or earlier](https://m00qek.github.io/luci-sso/0.10/how-to/sysadmin/upgrade/#before-you-upgrade-from-091-or-earlier); the upgrade page explains each change.

- **On OpenWrt 24.10, the upgrade logs every user out once, `root` included.** `opkg` runs 0.9.1's removal script, which restarts `rpcd`. Upgrade over SSH, not from LuCI's **Software** page.
- **Role permissions move to `rpcd`.** A role's `read` and `write` lists become the login entry `luci_sso_<role>` in `/etc/config/rpcd`, with the username `sso:<role>`. The upgrade moves them for you.
- **The first matching role wins.** A user who matches several roles gets the first one, in configuration order; rights are no longer merged. Check the order of your roles.
- **`*` has `rpcd`'s meaning.** It matches every access group, not only LuCI's. `read '*'` with `write '*'` is exactly what a `root` password login gets.
- **An `email` rule needs a verified email.** The new option `require_email_verified`, on by default, matches an email only when the IdP sends `email_verified: true`. Make the IdP send it, move users to `group` rules, or set the option to `0` before upgrading.
- **`issuer_url` must be the IdP's exact issuer**, character for character, including a trailing slash (OIDC Discovery §4.3).
- **The ID Token must have a single audience.** An `aud` that lists any client besides `client_id` fails with `AUDIENCE_MISMATCH` (OIDC Core §3.1.3.7).
- **`internal_issuer_url` must be an origin** (`https://host[:port]`); the issuer's path is added for you. A value with a path is rejected with `CONFIG_ERROR`, which turns SSO off. Reduce it to its origin right after installing, not before: 0.9.1 needs the path.
- **LuCI's Log out now ends the IdP session.** Register the origin of `redirect_uri` followed by `/` (for example `https://router.example.com/`) as a post-logout redirect URI at the IdP, or it shows an error page on logout.
- **On OpenWrt 25.12, end open sessions of a role named like an `rpcd` login**, such as `root`, before upgrading. Other SSO sessions opened before the upgrade lose their rights, and their users log in again.

### Added

- A `luci-sso` ubus object (`list_roles`, `set_role`, `delete_role`) that manages the roles' `rpcd` login entries. The settings page edits permissions through it, and says when a change takes effect.
- `require_email_verified`, and its **Require Verified Email** checkbox on the settings page.
- LuCI's own **Log out** entry sends SSO sessions through RP-Initiated Logout at the IdP. Every other session gets LuCI's own logout.
- `luci-sso-repatch`, which puts the login button back after a LuCI upgrade.
- Per-client rate limits: 10 login starts in 5 minutes and 30 requests a minute per client, instead of one global counter.
- Error pages in plain language, with a link back to the login page.
- Log lines that name the IdP's `error`, the issuer mismatch with both values, the missing or insecure discovery field, the cause of a failed back-channel request, the UCI option behind a `CONFIG_ERROR`, the role a user was mapped to, and each successful logout.
- The SSO button gives up after 15 seconds and says when the IdP is not responding.

### Changed

- SSO sessions get exactly the rights `rpcd` gives a password login with the role's entry, and keep them when `rpcd` reloads, for example when a LuCI package is installed.
- Every `read` list includes the `unauthenticated` access group, which LuCI needs on every page.
- SSO sessions use LuCI's session timeout, `luci.sauth.sessiontime`.
- A session is recognised as an SSO session by its username, `sso:<role>`, so a user matched by group whose IdP sends no email also logs out at the IdP.
- The session's `oidc_user` label holds the user's email only when the IdP marks it as verified, whatever `require_email_verified` says, so an address a user typed in themselves cannot make their session look like someone else's.
- From 0.10.0 on, upgrades and downgrades keep every session: the package reloads `rpcd` and never restarts it. The upgrade from 0.9.1 is the exception; see [Upgrade actions](#upgrade-actions). So is a rollback to 0.9.1, which [needs a removal first](https://m00qek.github.io/luci-sso/0.10/how-to/sysadmin/upgrade/#rolling-back-to-091-or-earlier). Removal copies the roles' permissions back onto the roles, and installing again moves them back.
- A failed request to the IdP is answered with `502 Bad Gateway`.
- The login button takes the theme's colours.
- A fresh install ships without a `redirect_uri`, so the settings page suggests one built from the host LuCI was opened at.
- The `iss` claim and the discovery `issuer` are compared exactly, the ID Token's `sub` must be a non-empty string, and a UserInfo `sub` must equal the ID Token's exactly (OIDC Core §2, §3.1.3.7, §5.3.2). Only the JSON boolean `true` counts as `email_verified` (OIDC Core §5.1).

### Removed

- The `move_role` method of the `luci-sso` ubus object. Role order is the order of `/etc/config/luci-sso`, which the settings page changes by drag and drop.
- The `MISSING_AT_HASH` and `MISSING_AZP_CLAIM` codes: `at_hash` and `azp` are optional, and checked when present.
- The unused secret key, `/etc/luci-sso/secret.key`, and the code that created it. An existing file is left in place and can be deleted.

### Fixed

- Every role below full administrator could see almost nothing, because only access-group names were granted.
- A role with only `read '*'` got full administrator rights.
- Split-horizon networking did not work for an issuer with a path, such as a Keycloak realm or an Authentik application.
- A flood of login requests could cancel logins in progress, and a forged callback link could end a victim's login.
- The Redirect URI suggested by the settings page was not saved unless it was edited.
- An `rpcd` reload in the middle of a login could leave the session with only part of its rights.

### Security

- The wolfSSL backend could read past the end of a PEM buffer when converting a key.
- The wolfSSL backend relied on the library's build options to refuse an EC point that is not on P-256; it now checks the point itself.
- The mbedtls backend accepted an EC key on any curve for ES256, and did not require an RSA key for RS256.

## [0.9.1] - 2026-09-21

### Fixed

- The login button appears on every LuCI theme, not only Bootstrap ([#10](https://github.com/m00qek/luci-sso/issues/10)).
- A session cookie left by an earlier password login no longer hides the SSO session, which sent users back to the login page after a successful login ([#11](https://github.com/m00qek/luci-sso/issues/11)).

## [0.9.0] - 2026-09-21

First public release.

[Unreleased]: https://github.com/m00qek/luci-sso/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/m00qek/luci-sso/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/m00qek/luci-sso/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/m00qek/luci-sso/releases/tag/v0.9.0
