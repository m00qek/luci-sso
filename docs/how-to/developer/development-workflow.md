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

Native C compilation is guarded by a sentinel file in `bin/lib/.built`. If you modify files in `src/`, the sentinel is invalidated and the next `make compile` rebuilds the C components.

---

## Test

Unit tests run inside the `openwrt` container, so the CI stack must be up first:

```bash
make -C devenv up
```

```bash
# Run all unit and integration tests (Tiers 0–4)
make -C devenv unit-test

# Run with detailed output
make -C devenv unit-test VERBOSE=1

# Run tests matching a pattern
make -C devenv unit-test FILTER='oidc.*discovery'

# Auto-run tests on file change
make -C devenv watch-tests
```

See [Running Tests](testing.md) for how to run individual tiers, and [Testing Architecture](../../reference/testing-architecture.md) for what each tier covers.

---

## E2E Tests

```bash
# Start the full OIDC test stack (mock IdP + router simulation)
make -C devenv up

# Run browser tests
make -C devenv e2e-test

# Tear down
make -C devenv down
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

If a check fails, see [How to add error codes, limit constants, and cookies](documented-interfaces.md) for what to update.

---

## Git Workflow

1. Create a branch: `git checkout -b feat/my-feature`
2. Make changes, run `make -C devenv unit-test` and `make -sC devenv lint` locally
3. Commit following the [commit message format](../../reference/style-guide.md#commit-messages)
4. Open a PR — CI runs the full test suite and lint checks automatically

---

## Stuck?

- Can't remember a formatting rule? Check existing code in `files/usr/share/ucode/luci_sso/`
- Unsure whether to throw or return a `Result`? See the [error handling decision tree](../../reference/style-guide.md#error-handling)
- API changed? Update the relevant doc in `docs/` before merging
