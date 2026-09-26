# How-to Guides

How-to guides are recipes. They take the reader through the steps required to solve a specific problem. They are goal-oriented.

---

## Identity Providers
*   [Generic OIDC Provider](providers/generic-oidc.md) - Azure AD, Okta, Dex, Zitadel, and others.
*   [Google](providers/google.md)
*   [Authelia](providers/authelia.md)
*   [Keycloak](providers/keycloak.md)
*   [Authentik](providers/authentik.md)
*   [Pocket ID](providers/pocket-id.md)
*   [GitHub](providers/github.md) - Not supported: why, and what to use instead.

## System Administration
*   [Installation](sysadmin/installation.md) - How to install the package and its dependencies.
*   [Configure in LuCI](sysadmin/configure-in-luci.md) - How to configure the OIDC settings and roles from the LuCI web interface.
*   [Installing a Private CA Certificate](sysadmin/install-ca-certificate.md) - How to make the router trust a self-signed or private CA certificate.
*   [Upgrading](sysadmin/upgrade.md) - How to upgrade to a new version and restore the login button after a LuCI upgrade.
*   [Rotating Credentials](sysadmin/rotate-credentials.md) - How to update the client secret or switch identity providers.
*   [Role-Based Access Control](sysadmin/rbac.md) - How to define who can access the router and what they can do.
*   [Split-Horizon Networking](sysadmin/split-horizon.md) - How to configure luci-sso when your router and browser reach the IdP via different addresses.
*   [Debugging & Logs](sysadmin/debugging.md) - How to troubleshoot authentication failures.
*   [Backing Up and Restoring Configuration](sysadmin/backup-restore.md) - How to preserve your configuration across a reflash or factory reset.
*   [Removing luci-sso](sysadmin/uninstall.md) - How to completely uninstall the package and restore password login.

## Development
*   [Development Workflow](developer/development-workflow.md) - The day-to-day loop: build, test, lint, and try changes in the local stack.
*   [Adding a New Crypto Backend](developer/adding-crypto-backend.md) - How to implement a new native C provider (e.g., for BoringSSL).
*   [Running Tests](developer/testing.md) - How to run each test bucket, a single file, or a filtered subset.
*   [Running the Fuzzer](developer/fuzzing.md) - How to run the coverage-guided fuzzer.
*   [Writing Documentation](developer/documentation.md) - How to use the documentation toolkit and standards.
*   [Adding Error Codes, Limits, and Cookies](developer/adding-documented-interfaces.md) - How to keep the code and the lint-checked reference pages in sync.
