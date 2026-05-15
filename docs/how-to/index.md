# How-to Guides

How-to guides are recipes. They take the reader through the steps required to solve a specific problem. They are goal-oriented.

---

## Identity Providers
*   [Generic OIDC Provider](providers/generic-oidc.md) - Azure AD, Okta, Dex, Zitadel, and others.
*   [Google OIDC](providers/google.md)
*   [GitHub OAuth2](providers/github.md)
*   [Authelia](providers/authelia.md)
*   [Keycloak](providers/keycloak.md)
*   [Authentik](providers/authentik.md)

## System Administration
*   [Installation](sysadmin/installation.md) - How to install the package and its dependencies.
*   [Configure in LuCI](sysadmin/configure-in-luci.md) - How to configure the OIDC settings and roles from the LuCI web interface.
*   [Installing a Private CA Certificate](sysadmin/install-ca-certificate.md) - How to make the router trust a self-signed or private CA certificate.
*   [Upgrading](sysadmin/upgrade.md) - How to upgrade to a new version without disrupting active sessions.
*   [Rotating Credentials](sysadmin/rotate-credentials.md) - How to update the client secret or switch identity providers.
*   [Role-Based Access Control](sysadmin/rbac.md) - How to define who can access the router and what they can do.
*   [Split-Horizon Networking](sysadmin/split-horizon.md) - How to configure luci-sso when your router and browser reach the IdP via different addresses.
*   [Debugging & Logs](sysadmin/debugging.md) - How to troubleshoot authentication failures.
*   [Backing Up and Restoring Configuration](sysadmin/backup-restore.md) - How to preserve your configuration across a reflash or factory reset.
*   [Removing luci-sso](sysadmin/uninstall.md) - How to completely uninstall the package and restore password login.

## Development
*   [Adding a New Crypto Backend](developer/adding-crypto-backend.md) - How to implement a new native C provider (e.g., for BoringSSL).
*   [Running Tests](developer/testing.md) - How to execute the different test tiers.
*   [Fuzz Testing](developer/fuzzing.md) - How to run the coverage-guided fuzzer.
*   [Writing Documentation](developer/documentation.md) - How to use the documentation toolkit and standards.
