# Changelog

All notable changes to `luci-sso` are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Until 1.0, a minor version may change the configuration or behaviour; each such change is listed under **Upgrade actions**.

## [0.10.2] - 2026-11-22

### Security

Upgrade to 0.10.2. No configuration change is needed, and existing sessions keep working.

- The IdP's `error` parameter on the callback, and other logged request values, were passed to `syslog` as a format string. An unauthenticated request holding printf conversions such as `%99999999d` could make the CGI build strings of hundreds of megabytes, and so use large amounts of memory. Every log line is now written as the argument of a constant `%s` format. 0.10.0 and 0.10.1 are affected.
- An SSO login in a browser that was already logged in to LuCI with a password kept running the password session. LuCI's own login sets its session cookie at `Path=/cgi-bin/luci/`, with a trailing slash, but the SSO callback and logout expired it only at `Path=/cgi-bin/luci`. Browsers tell cookies apart by their exact path, so the old cookie stayed, was sent first, and LuCI used it: the pages after the SSO login ran with the rights of the earlier login, `root` for instance, instead of the role's, and an SSO logout left that earlier session in the browser. The callback and `/cgi-bin/luci-sso/logout` now expire `sysauth_https`, `sysauth_http` and `sysauth` at both paths. 0.10.0 and 0.10.1 are affected.
- **Log out** ended nothing while the configuration could not be loaded: with SSO disabled, or any `CONFIG_ERROR`, `/cgi-bin/luci-sso/logout` answered 500 before it looked at the session, so an SSO session stayed valid until its timeout. Logout now always destroys the session and expires its cookies, after the same CSRF check; without a usable configuration it is local only, sends the browser to `/` instead of the IdP, and logs `Logout is local only: …`. 0.10.0 and 0.10.1 are affected.

## [0.10.1] - 2026-11-19

### Security

- On OpenWrt devices with libucode `2026.07.09~b885dd0f` or later, the regex engine of every 25.12 package index, a line feed in an untrusted value reached the log, and several checks accepted a value when only one of its lines passed. That ucode release (upstream commit 8a8b4d12) made `^` and `$` match at every line, and `.` and `[^...]` stop matching a line feed. An unauthenticated request could add forged lines to the system log through the callback's `error` and `error_description` parameters, because the log sanitiser no longer replaced the line feed. The handshake handle, Base64URL and role name checks, the URL parsing used for the issuer and discovery endpoints, the role list patterns, and the client address parsing of the rate limits now give the same answer on both engines: a value with a line feed is refused, or its line feed shown as `?`, as before. Devices on the older libucode, such as stock 24.10 and 25.12 images that were never upgraded, were not affected.

## [0.10.0] - 2026-09-29

### Upgrade actions

Upgrading from 0.9.1 needs some steps **before** you install, and one right after. Follow [Before you upgrade from 0.9.1 or earlier](https://m00qek.github.io/luci-sso/how-to/sysadmin/upgrade/#before-you-upgrade-from-091-or-earlier); the upgrade page explains each change.

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
- From 0.10.0 on, upgrades and downgrades keep every session: the package reloads `rpcd` and never restarts it. The upgrade from 0.9.1 is the exception; see [Upgrade actions](#upgrade-actions). So is a rollback to 0.9.1, which [needs a removal first](https://m00qek.github.io/luci-sso/how-to/sysadmin/upgrade/#rolling-back-to-091-or-earlier). Removal copies the roles' permissions back onto the roles, and installing again moves them back.
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

[0.10.2]: https://github.com/m00qek/luci-sso/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/m00qek/luci-sso/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/m00qek/luci-sso/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/m00qek/luci-sso/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/m00qek/luci-sso/releases/tag/v0.9.0
