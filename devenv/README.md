# LuCI SSO Development Environment

This directory contains a fully containerized OIDC/OAuth2 stack for developing and testing `luci-sso` without a physical router.

## 🏗️ Environment Stacks

The environment is split into two distinct **suites** (Docker Compose projects). While you can run one of each simultaneously, you cannot run two instances of the same suite.

### 1. Local Stack (`DOCKER_SUITE=local`)
*   **Purpose:** Manual development, hot-reloading code, and interactive debugging.
*   **Ports:** Maps services to `localhost` (e.g., 8443, 5556).
*   **Commands:** `make up`, `make down`, `make shell`.

### 2. E2E Stack (`DOCKER_SUITE=e2e`)
*   **Purpose:** Automated browser testing.
*   **Isolation:** Uses internal DNS names (e.g., `luci.luci-sso.test`) and does not map ports to the host to avoid conflicts with the Local stack.
*   **Commands:** `make e2e-up`, `make e2e-test`, `make e2e-down`.

> **Note on Concurrency:** You **CAN** have the Local stack running while you execute E2E tests. However, you **CANNOT** run `make e2e-up` twice simultaneously.

## 🌐 Accessing Services

The environment is designed to work via `localhost` using specific ports. All TLS certificates are generated with `localhost` in the Subject Alternative Name (SAN).

| Service | Local URL | Description |
| :--- | :--- | :--- |
| **LuCI** | [https://localhost:8443](https://localhost:8443) | The target OpenWrt web interface. |
| **Mock IdP** | [https://localhost:5556](https://localhost:5556) | The OIDC Identity Provider. |

## 🧪 Manual Testing & Debugging

Manual verification is highly encouraged during development to inspect token contents and redirection flows.

### 1. Verify OIDC Discovery
Check if the Mock IdP is serving its configuration correctly:
```bash
curl -k https://localhost:5556/.well-known/openid-configuration
```

### 2. Inspect Issued Tokens & Keys
The Mock IdP stores its runtime state (including generated signing keys) in:
*   `devenv/.pki/idp/signing_key.pem`
*   `devenv/.pki/idp/tokens.json` (if persistent storage is enabled in `index.js`)

### 3. Log Inspection
To follow logs for a specific component:
```bash
docker logs -f local-idp   # Mock IdP logs (Node.js)
docker logs -f local-luci  # uhttpd and ucode logs
```

### 4. Interactive Shell
If you need to inspect the LuCI state (UCI configs, UBUS) directly:
```bash
make shell CONTAINER=luci
```

## 🔐 PKI & Trust

The `pki` service automatically generates a development CA and per-service certificates on startup.
*   **CA Certificate:** Located at `devenv/.pki/CA.crt`.
*   **Trust:** To avoid browser TLS warnings, you can manually import `CA.crt` into your browser's trust store.
*   **Reset:** To regenerate all certificates, run `make down` and delete the `devenv/.pki` directory.

## 🛠 Troubleshooting

*   **Permission Denied on `bin/`:** Ensure the `bin/` directory is owned by your host user. If Docker created it as root, run `sudo chown -R $USER:$USER bin/`.
*   **Port Conflicts:** If ports 8443 or 5556 are in use, you can override them in `devenv/Makefile` or via environment variables.
