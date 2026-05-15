# How-to: Development Workflow

This guide covers the day-to-day development cycle for `luci-sso`.

---

## Prerequisites

- Docker (for the SDK build container and E2E test stack)
- `make`
- The repo checked out locally

All development commands go through `devenv/Makefile`, which delegates to `devenv/scripts/test.sh`.

---

## Build

```bash
# Build the IPK package for a specific architecture
make -C devenv package SDK_ARCH=x86-64

# Other common targets
make -C devenv package SDK_ARCH=aarch64_generic
make -C devenv package SDK_ARCH=mipsel_24kc
```

Native C compilation is guarded by a sentinel file at `bin/lib/<SDK_ARCH>/<SDK_VERSION>/.built`. If you modify files in `src/`, the sentinel is invalidated and the next `make -C devenv compile` rebuilds all available crypto backends in one pass.

---

## Test

Start the shared CI infrastructure first (IdP + headless Playwright browser):

```bash
make -C devenv infra-up DOCKER_SUITE=ci
```

```bash
# Run all unit and integration tests (Tiers 0–4)
make -C devenv test

# Run with detailed output
make -C devenv test VERBOSE=1

# Run tests matching a pattern
make -C devenv test FILTER='oidc.*discovery'

# Watch for file changes and re-run tests automatically
make -C devenv watch-tests
```

Each test target starts a fresh OpenWrt container, runs the tests against the shared infrastructure, and stops the container automatically. `watch-tests` keeps the container running across re-runs and tears it down on exit.

See [Running Tests](testing.md) for how to run individual tiers, and [Testing Architecture](../../reference/testing-architecture.md) for what each tier covers.

---

## E2E Tests

```bash
# Start CI infrastructure (if not already up)
make -C devenv infra-up DOCKER_SUITE=ci

# Run browser tests
make -C devenv e2e

# Tear down
make -C devenv infra-down DOCKER_SUITE=ci
```

---

## Environment Variables

Never hardcode environment-specific values (versions, domains) in Dockerfiles or tests. Always derive them from `devenv/Makefile` variables, which are passed through as `ARG` or `ENV` via Docker Compose.

---

## Lint

Three documentation contracts are enforced by CI. Run them locally before pushing:

```bash
make -sC devenv lint
```

If a check fails, see [How to add error codes, limit constants, and cookies](adding-documented-interfaces.md) for what to update.

---

## Git Workflow

1. Create a branch: `git checkout -b feat/my-feature`
2. Make changes, run `make -C devenv test` and `make -sC devenv lint` locally
3. Commit following the [commit message format](../../reference/style-guide.md#commit-messages)
4. Open a PR — CI runs the full test suite and lint checks automatically

---

## Stuck?

- Can't remember a formatting rule? Check existing code in `files/usr/share/ucode/luci_sso/`
- Unsure whether to throw or return a `Result`? See the [error handling decision tree](../../reference/style-guide.md#error-handling)
- API changed? Update the relevant doc in `docs/` before merging
