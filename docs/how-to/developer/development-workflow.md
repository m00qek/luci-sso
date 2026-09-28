# How to Work on luci-sso Day to Day

This guide covers the day-to-day development cycle for `luci-sso`.

---

## Prerequisites

- Docker (for the SDK build container and E2E test stack)
- `make`
- The repo checked out locally

All development commands go through `Makefile`. The test targets delegate to `devenv/scripts/test.sh`.

---

## Build

```bash
# Build the packages for a specific architecture (OpenWrt 24.10, .ipk)
make package SDK_ARCH=x86-64

# The same for OpenWrt 25.12 (.apk)
make package SDK_ARCH=x86-64 SDK_VERSION=25.12.3
```

The packages land in `bin/lib/<SDK_ARCH>/<SDK_VERSION>/packages/`. See [How to Build the Packages from Source](../sysadmin/build-from-source.md) for choosing the architecture and version.

Native C compilation is guarded by a sentinel file, `bin/lib/<SDK_ARCH>/<SDK_VERSION>/.built-<CRYPTO_LIB>`. When a file in `mod/` (`*.c`, `*.h` or `CMakeLists.txt`) is newer than the sentinel, the next `make compile` rebuilds the C components for that architecture, version and backend.

Each `make compile` and `make package` runs in a throwaway `sdk` container and leaves no Docker volume behind. The SDK images themselves take about 4.5 GB each for 24.10 and 25.12. Stop a stack with `make down` or `make local-down`, which also removes its containers' anonymous volumes.

Older versions of the devenv left an unnamed volume of about 1.3 GB after most `sdk` runs. To reclaim that space, list the dangling volumes, check that they are yours, and remove them one by one:

```bash
docker volume ls -f dangling=true
docker system df -v             # sizes, under "Local Volumes space usage"
docker volume rm <volume-name>
```

`docker volume prune` also removes the dangling volumes of every other project on the host.

---

## Test

Unit tests run inside the `openwrt` container against the native module that `make compile` builds, so build it and start the CI stack first:

```bash
make compile
make up
```

```bash
# Run the native, unit, integration and system tests
make unit-test

# Run with detailed output
make unit-test VERBOSE=1

# Run tests matching a pattern
make unit-test FILTER='discovery'

# Auto-run tests on file change
make watch-tests
```

See [Running Tests](testing.md) for how to run individual buckets and files, and [Testing Architecture](../../reference/testing-architecture.md) for what each bucket covers.

---

## E2E Tests

```bash
# Build the native module and start the full OIDC test stack (mock IdP + router simulation)
make compile
make up

# Run browser tests
make e2e-test

# Tear down
make down
```

---

## Environment Variables

Never hardcode environment-specific values (versions, domains) in Dockerfiles or tests. Always derive them from `Makefile` variables, which are passed through as `ARG` or `ENV` via Docker Compose.

---

## Lint

CI runs four lint checks: three documentation contracts and a code style check. Run them locally before pushing:

```bash
make lint
```

If a documentation check fails, see [How to add error codes, limit constants, and cookies](adding-documented-interfaces.md) for what to update. The code style check (`devenv/scripts/check-code-style.sh`) prints `file:line: rule: detail` for each violation; the rules are in the [style guide](../../reference/style-guide.md#enforcement).

---

## Blame past reformatting commits

Commits that only reformat code are listed in `.git-blame-ignore-revs`. To make `git blame` skip them and show the commit that last changed each line's content, run once in your clone:

```bash
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

GitHub's blame view reads the file without any setup. When you land a commit that only reformats code, add its full hash to the file in a follow-up commit.

---

## Prepare a pull request

1. Create a branch: `git checkout -b feat/my-feature`
2. Make your changes. Route any new I/O through `deps`, and keep C code to crypto primitives.
3. Add tests: every exported function you touched, every error path, and attack cases for security-critical code. See the [testing standards](../../reference/style-guide.md#testing-standards) for the minimum.
4. Run the tests and the lint checks:

    ```bash
    make compile
    make up
    make unit-test
    make e2e-test
    make lint
    ```

    `make test` runs `unit-test` and `e2e-test` together. If you changed `mod/`, also run `make fuzzer-test` and `make sanitizer-test`. CI runs both when `mod/` or the fuzz harness changes, and the sanitizer run also when `test/native/` or `test/unit/luci_sso/crypto/` changes.

    If your change touches only documentation (files under `docs/`, any `*.md` file, or `mkdocs.yml`), skip the test suites. Run `make lint` and a strict docs build instead, with `make -C docs build` (see [How to Write Documentation](documentation.md)).

5. Check the diff against the [style guide](../../reference/style-guide.md):
    - no secrets in code or log lines;
    - runtime failures return a `Result`, contract bugs `die()`;
    - names are `snake_case`, and exported functions end with `};`;
    - every `TODO` names an issue.
6. If you changed behaviour or an interface, update the matching page in `docs/` in the same pull request.
7. Commit following the [commit message format](../../reference/style-guide.md#commit-messages).
8. Open the pull request. CI runs the lint checks on every pull request. A pull request that changes only documentation (files under `docs/`, any `*.md` file, `mkdocs.yml` or `LICENSE`) skips the test workflow entirely. Otherwise the test suites run when the pull request changes `src/`, `mod/`, `files/`, `test/`, `openwrt/`, `Makefile`, or the `openwrt`, `idp`, `browser` or `pki` service under `devenv/services/`. CI builds the docs site with `--strict` whenever `docs/` or `mkdocs.yml` changes, the same as `make -C docs build`.

---

## Stuck?

- Can't remember a formatting rule? Check existing code in `src/`
- Unsure whether to throw or return a `Result`? See the [error handling decision tree](../../reference/style-guide.md#error-handling)
- API changed? Update the relevant doc in `docs/` before merging
