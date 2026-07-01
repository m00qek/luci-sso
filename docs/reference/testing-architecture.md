# Testing Architecture

`luci-sso` organises its tests into four **buckets** by scope and intended
assertion — not by which collaborators are faked. Faking is total and free at
every level (see [Core principle](#core-principle-everything-funnels-through-deps)),
so the dividing line is the **entry point** and what each test asserts.

| Bucket | Path | Entry point | System boundary (`deps`) | `luci_sso` collaborators |
|---|---|---|---|---|
| **native** | `test/native/` | `luci_sso.native` exports | n/a (is the boundary) | none — `native` (+ pure helpers) only |
| **unit** | `test/unit/**/*_test.uc` (mirrors `src/`) | one src module's exports | faked | may run for real, but incidental |
| **integration** | `test/integration/**/*_test.uc` | an orchestrator / composition seam | faked | real subgraph, asserted |
| **e2e** | `test/e2e/` (Playwright) | browser → real uhttpd/rpcd/IdP | real | real |

Run the unit/integration/native buckets with `make unit-test`; the browser
suite with `make e2e-test`; the C-level fuzzer with `make fuzzer-test`.

---

## Core principle: everything funnels through `deps`

All IO and nondeterminism enters through the `deps` object — `deps.fs`,
`deps.http`, `deps.ubus`, `deps.clock`, `deps.native`, `deps.log` — including the
`components/*` wrappers (`http_client`, `clock`), which are proxied in
`test/utest.config.uc` exactly like the C modules.

Consequently, **faking `deps` transitively controls a module _and its entire
static-import subgraph_.** It works identically for a leaf (`crypto/base`) and an
orchestrator (`handshake`) — the orchestrator just pulls its real collaborators
along, all driven by the same fake `deps`.

Therefore **"what is mocked" is _not_ the unit/integration dividing line** —
faking is total at every level. The line is **scope + intended assertion**, i.e.
the entry point.

---

## Unit vs integration

- **unit** — entry is one module's exported function; assert *that module's
  input→output contract*; the system boundary is faked. If the module's static
  imports are all pure or transparent-through-`deps`, this genuinely isolates it.
- **integration** — entry is an orchestrator (`handshake`, `router`) or a wiring
  seam (`deps.create`, the CGI `main`); faking `deps` unavoidably runs a
  multi-module subgraph; assert *cross-module wiring and invariants*. Split by
  **scenario** (`describe` blocks), not by sub-module.

### Placement rule

> A module *M* gets an **integration** file iff faking `deps` for *M*
> transitively executes *other non-pure modules* (i.e. *M* is an orchestrator).
> Otherwise *M* is deps-isolable → **unit** file only.

| src module(s) | deps-faked test runs… | bucket |
|---|---|---|
| `crypto/*`, `encoding`, `result`, `config`, `web`, `errors` | itself (+ pure leaves) | unit |
| `discovery`, `oidc`, `ubus`, `session/*`, `components/*` | itself + pure leaves | unit |
| `handshake` | real `oidc + discovery + session + ubus + config` | integration |
| `router` | real `handshake + web + session + ubus + config` | integration |
| `deps` (`create()`) / CGI entry | wires the whole graph vs real system modules | integration |

`integration/` is **not** a `src/` mirror — only orchestrators appear
(`handshake_test.uc`, `router_test.uc`, `logout_test.uc`). Two honest
consequences:

1. `unit/` is not a perfect `src/` mirror either — `handshake`, `router` and
   `deps` have no unit file (no isolable unit surface).
2. `session.uc` is a pure façade (`get_secret_key = key.get`,
   `verify_state = handshake.verify`, …). Its wiring is covered by
   `unit/luci_sso/session_test.uc`; the submodules' behaviour lives in
   `unit/luci_sso/session/{key,handshake,token,common}_test.uc`.

---

## The `native` bucket

`native` has no `src/*.uc` — it is `mod/*.c` reached over the ucode FFI, so it
mirrors `mod/`, not `src/`. Its job is **the C extension's exported contract**:
correct crypto outputs (KAT vectors), memory safety, hardening, and the
boundary/error behaviour of the seven exports (`random`, `sha256`,
`hmac_sha256`, `verify_rs256`, `verify_es256`, `jwk_rsa_to_pem`,
`jwk_ec_p256_to_pem`). It is the **primary gate for swapping crypto backends**
(mbedtls / wolfssl / openssl).

Rules:

- Import **only** `luci_sso.native` (plus pure helpers like `encoding` as
  scaffolding). Do **not** route through `luci_sso.crypto` — that is wrapper
  coverage, which belongs to the crypto unit tests.

`native.c` gets three tiers of coverage; this bucket is one of them:

1. **C-level libFuzzer** (`make fuzzer-test`) — deepest / adversarial.
2. **native conformance** (this bucket) — the FFI contract.
3. **transitive** — every crypto/orchestrator test hits real `native.c`
   incidentally.

### `unit/crypto/*` mocks `native`

The crypto wrappers pass `native` as an explicit argument, so their unit tests
inject a literal fake (`crypto.jws_verify({ hmac_sha256: () => 'sig' }, …)`) —
no proxy needed. This keeps `native_test.uc` the single source of
crypto-correctness truth, lets a fake deterministically hit failure branches real
crypto won't produce (`verify_rs256 → false ⇒ INVALID_SIGNATURE`), and keeps the
wrappers green regardless of the compiled backend. Real-wrapper-over-real-crypto
coverage still exists transitively in integration and e2e.

---

## Mocking: the proxy DSL

The system boundary is faked with `mock.inject_all` (or `mock.inject` for a
single module), which hands back **proxies** driven by a spec:

```javascript
import { mock, spy } from 'utest';

mock.inject_all({
    fs:    { strict: true, data: { '/etc/luci-sso/secret.key': SECRET } },
    clock: { strict: true, data: { now: 1700000000 } },
}, (injected) => {
    let deps = { fs: injected.fs, clock: injected.clock, native, log: () => null };
    let res  = key.get(deps);

    assert.match(contains({ ok: true, data: SECRET }), res);
    assert.match('/etc/luci-sso/secret.key', spy(injected.fs).calls.readfile[0][0]);
});
```

Guidelines:

- **Prefer `mock.inject_all`; never hand-write a stub object when a proxy
  exists.** `fs`, `uci`, `ubus`, `uloop`, and the `http_client` / `clock` /
  `native` components are all proxied.
- **Prefer `data:` over `behavior:`.** Reach for a `behavior:` callback only when
  the response must depend on call arguments or count.
- Use `strict: true` so any un-modelled call dies loudly.
- Inspect side effects with `spy(proxy).calls.<fn>` (an array of argument
  tuples).
- Integration and deps-graph-heavy unit tests build the full `deps` object via
  `with_context(cfg, cb)` (`test/context.uc`), which assembles every proxy into
  a real `deps` and seeds the runtime state files.

Shared fixtures live in `test/fixtures/` (`fixtures.rsa`, `fixtures.oidc`,
`fixtures.anchor`); real signed JWTs come from `test/lib/helpers.uc`
(`lib.helpers`).

---

## Execution model (parallelism)

`utest` runs **each `_test.uc` file in its own process**, up to *X* jobs
concurrently (*X* ≈ core count). The parallelism unit is therefore **the file**:

- Splitting a slow file into several `_test.uc` files parallelises it for free.
- **Wall-time floor = the single longest file.** Balance heavy cases (RSA-4096
  verify, high-iteration property tests) across files.
- Per-file process startup (module load + `native_crypto_init()`) is paid once
  per file, so don't over-split — tiny files let startup dominate. Split a file
  only once it becomes a multi-second long pole.

---

## Minimum coverage per exported function

- One success case (happy path).
- One error case per error type / branch.
- Edge cases (empty input, `null`, boundary values).
- Security cases where relevant (tampering, injection, replay, alg confusion,
  bypass attempts). Security-critical code **must** include attack tests.

All tests **must** run offline, with no external network dependency.
