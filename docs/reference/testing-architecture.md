# Testing Architecture

The test buckets, which source module belongs in which, and the mocking interface. For why the suite is divided this way, see [About the Test Architecture](../explanation/test-architecture.md). The rules every test must follow are in the [Style Guide](style-guide.md#testing-standards).

---

## Buckets

| Bucket | Path | Entry point | System boundary (`deps`) | `luci_sso` collaborators |
|---|---|---|---|---|
| **native** | `test/native/` | `luci_sso.native` exports | n/a (is the boundary) | none: `native` (+ pure helpers) only |
| **unit** | `test/unit/**/*_test.uc` (mirrors `src/`) | one src module's exports | faked | may run for real, but incidental |
| **integration** | `test/integration/*_test.uc` | an orchestrator or wiring seam | faked | real subgraph, asserted |
| **system** | `test/system/` | the real rpcd in the openwrt container, no browser | real | real |
| **e2e** | `test/e2e/` (Playwright) | browser → real uhttpd/rpcd/IdP | real | real |

| Command | Runs |
| :--- | :--- |
| `make unit-test` | native, unit, integration and system, in the `openwrt` container |
| `make e2e-test` | e2e. Each spec file is its own Playwright invocation, and the rate-limit state is reset before each. |
| `make fuzzer-test` | the C-level libFuzzer harness, `test/fuzz_test.c` |
| `make sanitizer-test` | native and `unit/luci_sso/crypto` against a module built with AddressSanitizer and UndefinedBehaviorSanitizer |

See [How to Run Tests](../how-to/developer/testing.md) for the options of each command.

---

## Placement rule

> A module *M* gets an **integration** file if and only if faking `deps` for *M*
> transitively executes *other non-pure modules* (*M* is an orchestrator).
> Otherwise *M* is deps-isolable and gets a **unit** file only.

| src module(s) | A deps-faked test runs… | Bucket | Test file(s) |
|---|---|---|---|
| `crypto/*`, `crypto`, `encoding`, `result`, `config`, `web` | itself (+ pure leaves) | unit | `unit/luci_sso/<module>_test.uc`, `unit/luci_sso/crypto/*_test.uc` |
| `discovery`, `oidc`, `ubus`, `ratelimit`, `session`, `session/*`, `components/*` | itself + pure leaves | unit | `unit/luci_sso/…` (mirrors `src/`) |
| `handshake` | real `oidc`, `discovery`, `session`, `ubus`, `config` | integration | `handshake_test.uc` |
| `router` | real `handshake`, `session`, `ubus`, `discovery`, `config`, `ratelimit` | integration | `router_test.uc`, `logout_test.uc` |
| `entry` (CGI `run()` pipeline) | real `web`, `config`, `router` and everything below it | integration | `entry_test.uc` |
| `deps` (`create()` and its channel builders) | the production wiring | integration | `bootstrap_test.uc` |
| `luci.controller.sso` (`files/usr/share/ucode/luci/controller/sso.uc`, `action_logout`) | the controller, with LuCI's `ctx`, `http` and `ubus` globals faked | integration | `luci_logout_test.uc` |
| `errors` | n/a | none | `make lint` checks it against [Log Messages](log-messages.md) |

`handshake`, `router`, `entry` and `deps` have no unit file. `session.uc` re-exports `session/handshake.uc` (`create_state = handshake.create`, `verify_state = handshake.verify`, …); `unit/luci_sso/session_test.uc` covers that wiring and `unit/luci_sso/session/{handshake,common}_test.uc` cover the behaviour.

---

## The `native` bucket

`test/native/native_test.uc` covers the seven exports of `luci_sso.native` (`mod/*.c`): `random`, `sha256`, `hmac_sha256`, `verify_rs256`, `verify_es256`, `jwk_rsa_to_pem` and `jwk_ec_p256_to_pem`. It asserts known-answer vectors (`test/native/fixtures.uc`), memory safety, hardening, and boundary and error behaviour.

- It imports **only** `luci_sso.native`, plus pure helpers such as `encoding` as scaffolding. It does not import `luci_sso.crypto`.
- `unit/luci_sso/crypto/*` tests fake `native` with `mock.inject('native', { strict: true, data: { … } }, …)`, through `test/proxies/native.uc`. They do not assert crypto correctness.

| Coverage of the native module | Reaches |
| :--- | :--- |
| `make fuzzer-test` | the guarded entry points in `mod/native_api.c` and the backend; not the ucode binding (`mod/native_ucode.c`) |
| native bucket | the compiled module, binding included |
| every other ucode test | the real module, incidentally, wherever `native` is not faked |

---

## The `system` bucket

The system bucket drives the container's real `rpcd`. Its files run one at a time, after the other buckets, because its tests make `rpcd` reload, and a reload briefly removes its ubus objects.

| File | Covers |
| :--- | :--- |
| `test/system/rpcd_parity_test.uc` | SSO sessions against `rpcd` password logins. For each role shape (read `*`; a specific read group; a specific write group; read `*` with one write group; globs with a negation; read and write `*`; a restricted read list with `unauthenticated`; `unauthenticated` only; a read negation against the write list; single options instead of lists), it creates a password login and a `luci_sso_<role>` entry with the same lists, logs in both ways through the real code, and requires identical ACLs, printing every entry that differs. |
| `test/system/sso_session_test.uc` | SSO sessions across an `rpcd` reload keep exactly their rights. A login interrupted by a reload before any of its `ubus` calls still ends with the role's full rights. A session named `sso:root` gets no rights, although a `root` login exists. `luci-sso` refuses to create a session for a role whose entry is missing (`MISSING_RPCD_LOGIN`) or has a password (`INSECURE_RPCD_LOGIN`). |
| `test/system/rpcd_plugin_test.uc` | The `luci-sso` ubus object inside the real `rpcd`: `set_role`, `list_roles` and `delete_role`; the `unauthenticated` rule; password removal; validation errors; `reload_pending`; existing sessions getting new rights after the reload; the exact method list. Its roles are named `systest_*`. |
| `test/system/migration_test.uc` | `rpcd_login.migrate()` and `demigrate()` on real UCI files in a scratch configuration directory: an old-style configuration, the shipped `admin` role and edited ones, second runs, interrupted runs, and the migrate, demigrate, migrate round trip, byte for byte. |

CI runs the bucket on every OpenWrt release in the matrix.

---

## Mocking: the proxy DSL

The system boundary is faked with `mock.inject_all` (or `mock.inject` for a single module), which hands back **proxies** driven by a `{ strict, data, behavior }` spec:

```javascript
import { mock, spy } from 'utest';

mock.inject_all({
    fs:    { strict: true,
             data: { '/var/run/luci-sso/handshake_abc.json': '{}' },
             behavior: { stat: () => ({ mtime: 1700000000 - 1000 }) } },
    clock: { strict: true, data: { now: 1700000000 } },
}, (injected) => {
    let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
    let res  = handshake.reap(deps, 0);

    assert.match(contains({ ok: true, data: 1 }), res);
    assert.match('/var/run/luci-sso/handshake_abc.json', spy(injected.fs).calls.unlink[0][0]);
});
```

| Element | Meaning |
| :--- | :--- |
| `strict: true` | Any call the spec does not model dies. |
| `data:` | Canned values: file contents for `fs`, `{ now }` for `clock`, URL → `{ status, body }` for `http_client`, return values by function name for `native`. |
| `behavior:` | Callbacks that compute a response from the call arguments or count. |
| `spy(proxy).calls.<fn>` | The recorded calls, as an array of argument tuples. |
| Proxied modules | `fs`, `uci`, `ubus`, `uclient`, `uloop` (built into utest), and `http_client`, `clock`, `native` (`test/proxies/`), as configured in `test/utest.config.uc`. |

### `with_context`

`with_context(cfg, cb)` (`test/context.uc`) injects a proxy for every key of `cfg`, builds a full `deps` object from them, and passes it to `cb`:

| `deps` field | Built from |
| :--- | :--- |
| `fs` | the `fs` proxy, strict, seeded with an empty `/var/run/luci-sso/ratelimit.json` and `/usr/share/rpcd/acl.d/luci-base.json` |
| `uci` | `uci.cursor()` on the strict proxy, seeded with `luci.sauth.sessiontime = 3600` |
| `ubus` | the production `ubus_channel()` over the proxy connection. `UBUS_NO_DATA` stands for a successful call with no reply. |
| `http` | `http_client.create()` on the proxy |
| `clock` | `clock.create()` on the proxy |
| `native` | the real compiled module, unless `cfg.native.behavior` is set |
| `log` | a no-op |

Shared fixtures live in `test/fixtures/` (`fixtures.rsa`, `fixtures.oidc`); real signed JWTs come from `test/lib/helpers.uc` (`lib.helpers`).

---

## Execution model

| Property | Value |
| :--- | :--- |
| Process | Each `_test.uc` file runs in its own `ucode` process, so module load and `native_crypto_init()` happen once per file. |
| Concurrency | One file at a time. `devenv/scripts/test.sh` runs the `system` bucket in a separate `utest` run, after the others, with `-j 1`; the other buckets get no `-j`, and `test/utest.config.uc` sets no `jobs`, so utest 1.5.1 runs them one at a time too. `-j N` or a `jobs` config key runs *N* files in parallel, which the `system` bucket must never do. A `MODULES` selection is split the same way, and the command fails if either run fails. |
| Timeout | 60 seconds per file (utest default; `timeout` config key). |
| Bundles | The directories `test.sh` passes to `utest`: `native`, `integration`, `unit/luci_sso`, `unit/luci_sso/components`, `unit/luci_sso/crypto`, `unit/luci_sso/session`, `system`. |
