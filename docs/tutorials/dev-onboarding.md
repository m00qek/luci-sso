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

## Step 2: Launch the development stack

Now we'll start the "Mock Environment" — a fake Identity Provider (IdP) and a simulated OpenWrt instance running in containers:

```bash
make -C devenv up
```

After a moment, you should see all containers report as healthy. The mock IdP is pre-configured with test credentials so we don't need a real Google or Authelia account.

## Step 3: Run the test suite

Let's verify everything is working correctly:

```bash
make -C devenv unit-test
```

You should see a series of green checkmarks for Tiers 0 through 4, ending with a summary like:

```
All tests passed. (Tier 0: 12, Tier 1: 8, Tier 2: 24, Tier 3: 9, Tier 4: 3)
```

If any tier fails, the output will identify the failing test and the module it belongs to.

## Step 4: Try the login flow

We can now access the LuCI web interface running inside the container:

* **URL:** `https://localhost:8443`
* Choose **"Login with SSO"** to trigger the OIDC flow against the mock IdP.

Notice that the login redirects to the mock IdP, then back to LuCI — the same flow a real user experiences with Google or Authelia. The mock IdP accepts any credentials, so any username/password will work.

---

## What we just built

* A native C crypto bridge compiled for the local architecture, loaded by `ucode` for cryptographic operations.
* A mock Identity Provider pre-configured with test credentials that accepts any username and password.
* A simulated OpenWrt instance running `luci-sso` in a container, accessible at `https://localhost:8443`.
* A full test suite covering Tiers 0–4, runnable without a physical router or a real IdP.

---

## Next steps

We now have a working development environment. From here:

* Learn how to [run specific tests or filter by module](../how-to/developer/testing.md)
* Understand the daily [development workflow](../how-to/developer/development-workflow.md)
* Read the [Architecture explanation](../explanation/architecture.md) to understand how the pieces fit together
