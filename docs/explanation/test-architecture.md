# About the Test Architecture

`luci-sso` sorts its tests into five buckets: native, unit, integration, system and e2e. The obvious way to draw those lines would be by what each test fakes. This project draws them by where a test enters the code and what it asserts instead. This page explains why. For the buckets themselves, the placement table and the mocking interface, see the [Testing Architecture reference](../reference/testing-architecture.md).

---

## Everything funnels through `deps`

As [About the Architecture](architecture.md#all-io-goes-through-deps) describes, no module reaches the outside world on its own. The filesystem, HTTP, ubus, UCI, the clock, the crypto bridge and the log all arrive through one injected object, `deps`. That includes the project's own `components/*` wrappers (`http_client`, `clock`), which the test configuration proxies exactly like the system modules.

The consequence is that faking `deps` controls a module *and everything it imports*. A fake `deps` drives a leaf such as `crypto/base` in exactly the same way as it drives the `handshake` orchestrator. The orchestrator simply brings its real collaborators along, and they all run against the same fake.

So faking is total at every level, and it costs nothing. "What is mocked" cannot separate a unit test from an integration test, because the answer is always the same: the system boundary. What differs is the scope of the test, which is set by its entry point.

---

## Unit and integration are about scope

A **unit** test enters at one module's exported function and asserts that module's contract: this input produces this output or this error. If everything the module imports is pure, or reaches the system only through `deps`, the test genuinely isolates it. Other modules may run for real underneath, but the test is not about them.

An **integration** test enters at an orchestrator (`handshake`, `router`) or a wiring seam (`deps.create()`, the CGI `run()` pipeline). Faking `deps` there unavoidably runs a subgraph of several modules, and that is the point: the test asserts that they are wired together correctly and that invariants hold across them. Such files are organised by scenario (a `describe` block per flow) rather than by sub-module, because the scenario is what they check.

Two things follow that can look like gaps:

- **`unit/` is not a perfect mirror of `src/`.** `handshake`, `router`, `entry` and `deps` have no unit file. They have no isolable surface: any test that enters them runs their collaborators, which makes it an integration test by definition.
- **`integration/` is not a mirror at all.** Only orchestrators and wiring seams appear there. A module with nothing to compose has nothing to integrate.

`oidc` is the borderline case. It imports `find_jwk` from `discovery`, so its tests run real `discovery` code, yet it is filed as unit because its tests enter at `oidc` and assert `oidc`'s contract.

---

## Why the native module has its own bucket

The native module is C code in `mod/`, reached from ucode through the FFI. It has no `src/*.uc`, so it mirrors `mod/`, not `src/`. Its bucket checks the C extension's exported contract: correct outputs against known-answer vectors, memory safety, and the boundary and error behaviour of each export.

That bucket is the main gate for swapping crypto backends. mbedTLS, wolfSSL and OpenSSL must all pass the same file, so the file must say everything there is to say about crypto correctness. This is why it imports only `luci_sso.native` and never the `crypto` wrappers: a failure should point at the backend, not at wrapper logic above it.

The same reasoning explains why the `crypto/*` unit tests fake `native` rather than use it:

- **One source of truth.** If the wrapper tests also ran real crypto, a backend swap would re-check correctness in two places, and wrapper tests would fail for backend reasons.
- **Reachable failure branches.** The wrappers' real job is shaping Results, guarding inputs and mapping errors. A fake can make `verify_rs256` return `false` or `sha256` return `null` on demand; real crypto will not produce those failures for a test.
- **Backend independence.** Wrapper logic is the same whichever backend is compiled, so its tests should pass regardless of it.

Real wrappers over real crypto are still exercised, just elsewhere: every integration and e2e test that verifies a token goes through both.

The native module is therefore covered three ways, each reaching a different depth. The C-level fuzzer drives the guarded entry points with adversarial input. The native bucket checks the contract through the compiled module, binding included. And every other test uses the real module incidentally.

---

## Why there is a system bucket, and why it is small

`luci-sso` creates LuCI sessions itself, so it must grant the same concrete rights `rpcd` would give a password login with the role's entry. It must, because `rpcd` rebuilds every session from that entry when it reloads: any difference would change a user's rights at the next reload. The group definitions are read from `rpcd`'s own ACL files at every login, but the rules for combining them (write implies read, table and array notation, globs, negations checked first, lists only) are a copy of `rpcd`'s C code. A copy can drift. When a new OpenWrt release changes those rules, faked `deps` cannot notice, because the fake encodes the old rules.

The system bucket exists to catch exactly that, and a few other things only the real daemon can show: that a session survives a reload with the same rights, that a session named `sso:root` never gets `root`'s rights, that the `luci-sso` ubus object works inside `rpcd`, and that the install and removal scripts' migration is exact on real UCI files. It is kept for invariants that need the real daemon. Everything else stays in unit and integration tests, where faked `deps` makes tests fast, deterministic and runnable offline.

Because its tests make `rpcd` reload, and `rpcd` briefly has no ubus objects while it restarts, the system bucket runs one file at a time, after the others.

---

## Why proxies rather than hand-written stubs

The mocking interface prefers `mock.inject_all` proxies over stub objects written in each test, `data:` over `behavior:`, and `strict: true`. Each preference trades a little convenience for honesty. A proxy records every call, so a test can assert on side effects without extra code. Canned `data:` keeps a fake declarative, whereas a `behavior:` callback is code that can itself be wrong. Strict mode makes an unmodelled call fail loudly instead of returning something plausible. And `with_context` builds `deps` through the production `ubus_channel()`, so tests run the same reply handling the router does.

---

## Why test files are the unit of execution

utest runs each `_test.uc` file in its own `ucode` process. This isolates files from each other, since a mock or a crashed worker cannot leak into the next file, but it has a cost: every file pays for loading its modules and initialising the crypto library once.

That shapes how tests are split. Many tiny files let start-up time dominate. One huge file is slow to rerun and, when files run in parallel, it becomes the floor on wall time, since a run cannot finish before its longest file. The suite currently runs one file at a time. If parallel jobs are turned on, the heavy cases (RSA-4096 verification, high-iteration property tests) are worth spreading across files. Until a file becomes a multi-second long pole, splitting it gains nothing.

---

## Related

- [Testing Architecture](../reference/testing-architecture.md) — the buckets, placement table, proxy DSL and execution model.
- [Style Guide: Testing Standards](../reference/style-guide.md#testing-standards) — the rules every test must follow.
- [How to Run Tests](../how-to/developer/testing.md) — commands for each bucket.
