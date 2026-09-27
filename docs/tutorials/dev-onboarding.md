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

The mock IdP signs everyone in as the same test user, `admin@example.com` — no real Google or Authelia account is needed. All SSO traffic stays on the local machine.

---

## Prerequisites

* **Docker** and **Docker Compose** (V2).
* **make** utility.

## Step 1: Build the native components

First, let's compile the native C crypto bridge for the default architecture:

```bash
make compile
```

You should see the build system produce a `.so` file in `bin/lib/`. This C bridge is what `ucode` loads for cryptographic operations.

## Step 2: Launch the development stack

Now we'll start the "Mock Environment" — a fake Identity Provider (IdP) and a simulated OpenWrt instance running in containers:

```bash
make up
```

After a moment, you should see all containers report as healthy.

## Step 3: Run the test suite

Let's verify everything is working correctly:

```bash
make unit-test
```

You should see a row of green dots for each bundle — the native crypto tests, the unit tests and the integration tests — ending with a summary like:

```
Summary:

  594 successes / 0 failures / 0 errors / 0 skipped / 0 ignored (3500 ms)
```

The exact count grows as tests are added. If a test fails, rerun with `make unit-test VERBOSE=1` to see each test's name and the failing assertion.

## Step 4: Try the login flow

The CI stack from Step 2 runs entirely inside Docker with no ports exposed to your machine — it is designed for automated tests. To interact with LuCI from a browser, start the local suite, which binds ports on `localhost`:

```bash
make local-up
```

Then open `https://localhost:8443` in your browser and choose **"Login with SSO"** to trigger the OIDC flow against the mock IdP.

Notice that the login goes to the mock IdP and straight back to LuCI. The mock IdP has no login form: it approves every request at once and issues an ID Token for `admin@example.com`, which the default `admin` role accepts. Apart from that missing step, it is the same flow a real user experiences with Google or Authelia.

---

## What we just built

* A native C crypto bridge compiled for the local architecture, loaded by `ucode` for cryptographic operations.
* A mock Identity Provider that signs every login in as `admin@example.com`, without a login form.
* A CI stack (`make up`) for running the test suite, and a local stack (`make local-up`) with ports exposed for browser-based interaction at `https://localhost:8443`.
* A full test suite — native, unit, integration and browser end-to-end — runnable without a physical router or a real IdP.

---

## Next steps

We now have a working development environment. From here:

* Learn how to [run specific tests or filter by module](../how-to/developer/testing.md)
* Understand the daily [development workflow](../how-to/developer/development-workflow.md)
* Read the [Architecture explanation](../explanation/architecture.md) to understand how the pieces fit together
