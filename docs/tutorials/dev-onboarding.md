# Developer Onboarding

In this tutorial, we will set up a local development environment, run the full test suite, and verify a working SSO login flow against a mock Identity Provider. By the end, we'll have a running stack we can develop against.

---

## What we will build

```
┌──────────────────────────────────────────────────────┐
│  Local machine                                       │
│                                                      │
│  ┌─────────────────────┐     ┌────────────────────┐  │
│  │  Mock OpenWrt       │     │  Mock IdP          │  │
│  │  (container)        │ ◄── │  (container)       │  │
│  │  luci-sso @ :8443   │     │  pre-configured    │  │
│  └─────────────────────┘     └────────────────────┘  │
│           ▲                                          │
│    browser / test suite                              │
└──────────────────────────────────────────────────────┘
```

The mock IdP is pre-configured with test credentials — no real Google or Authelia account is needed. All SSO traffic stays on the local machine.

---

## Prerequisites

* **Docker** and **Docker Compose** (V2).
* **make** utility.

## Step 1: Build the native components

First, let's compile the native C crypto bridge for the default architecture:

```bash
make -C devenv compile
```

You should see the build system produce a `.so` file in `bin/lib/`. This C bridge is what `ucode` loads for cryptographic operations.

## Step 2: Try the login flow

Start the local stack, which exposes the simulated router on `localhost`:

```bash
make -C devenv up
```

After a moment, all containers report as healthy. Open `https://localhost:8443` in your browser and choose **"Login with SSO"** to trigger the OIDC flow against the mock IdP.

Notice that the login redirects to the mock IdP, then back to LuCI — the same flow a real user experiences with Google or Authelia. The mock IdP accepts any credentials, so any username/password will work.

## Step 3: Run the test suite

The automated test suite runs against a CI infrastructure stack that includes a headless Playwright browser container. Start it first:

```bash
make -C devenv infra-up DOCKER_SUITE=ci
```

Then run the tests:

```bash
make -C devenv test
```

Each test target starts a fresh OpenWrt container, runs the tests, and stops it automatically. You should see a series of green checkmarks for Tiers 0 through 4, ending with a summary like:

```
All tests passed. (Tier 0: 12, Tier 1: 8, Tier 2: 24, Tier 3: 9, Tier 4: 3)
```

If any tier fails, the output will identify the failing test and the module it belongs to.

When done, stop the infrastructure:

```bash
make -C devenv infra-down DOCKER_SUITE=ci
```

The local stack from Step 2 and the CI infrastructure can run simultaneously without interfering — they are separate Docker Compose projects sharing a private network.

---

## What we just built

* A native C crypto bridge compiled for the local architecture, loaded by `ucode` for cryptographic operations.
* A mock Identity Provider pre-configured with test credentials that accepts any username and password.
* A local stack (`make -C devenv up`) with ports exposed for browser-based interaction at `https://localhost:8443`.
* A CI infrastructure stack (`make -C devenv infra-up DOCKER_SUITE=ci`) that runs the IdP and headless Playwright browser, shared across all test runs.
* A full test suite covering Tiers 0–4, where each test target manages its own OpenWrt container lifecycle.

---

## Next steps

We now have a working development environment. From here:

* Learn how to [run specific tests or filter by module](../how-to/developer/testing.md)
* Understand the daily [development workflow](../how-to/developer/development-workflow.md)
* Read the [Architecture explanation](../explanation/architecture.md) to understand how the pieces fit together
