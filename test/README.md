# Tests

Native, unit, integration, and end-to-end tests for `luci-sso`.

For the full rationale, see
[Testing Architecture](https://m00qek.github.io/luci-sso/reference/testing-architecture/)
and [How to Run Tests](https://m00qek.github.io/luci-sso/how-to/developer/testing/).

---

## Running tests

```bash
make unit-test                          # native + unit + integration
make unit-test VERBOSE=1                # with per-test output
make unit-test FILTER='session.key'     # regex filter on test titles
make unit-test MODULES='test/unit/luci_sso/oidc_test.uc'  # a single file/dir

make up && make e2e-test                # full browser E2E (requires Docker)
make -sC devenv fuzzer-test CRYPTO_LIB=mbedtls  # C-level fuzzer (~60s)
```

## Buckets

| Bucket | Path | Entry point |
| :--- | :--- | :--- |
| **native** | `native/` | `luci_sso.native` FFI exports (crypto KAT, memory safety, hardening) |
| **unit** | `unit/**` (mirrors `src/`) | one module's exported function; system boundary faked |
| **integration** | `integration/**` | an orchestrator/wiring seam (`handshake`, `router`, `logout`) |
| **e2e** | `e2e/` | Playwright → real uhttpd/rpcd/IdP |

Shared helpers: `fixtures/` (`fixtures.rsa`, `fixtures.oidc`, `fixtures.anchor`),
`lib/helpers.uc` (real signed JWTs), `context.uc` (`with_context` deps builder),
`proxies/` (component proxies). Module resolution and the proxied modules are
configured in `utest.config.uc`.

---

## Mocking quick reference

The system boundary is faked with `mock.inject_all` (or `mock.inject`), which
returns **proxies** driven by a `{ strict, data, behavior }` spec. Prefer
`data:` over `behavior:`; never hand-write a stub object when a proxy exists.

```javascript
import { describe, it, assert, contains, spy, mock } from 'utest';
import * as key from 'luci_sso.session.key';

describe('session.key: get', () => {
    it('returns the on-disk secret', () => {
        mock.inject_all({
            fs:    { strict: true, data: { '/etc/luci-sso/secret.key': SECRET } },
            clock: { strict: true, data: { now: 1700000000 } },
        }, (injected) => {
            let deps = { fs: injected.fs, clock: injected.clock, native, log: () => null };
            assert.match(contains({ ok: true, data: SECRET }), key.get(deps));
            assert.match('/etc/luci-sso/secret.key', spy(injected.fs).calls.readfile[0][0]);
        });
    });
});
```

Integration and deps-graph-heavy tests use `with_context(cfg, cb)`, which
assembles every proxy into a full `deps` object and seeds the runtime state.

## Assertions (utest)

| Form | Passes when |
| :--- | :--- |
| `assert.match(expected, actual, [msg])` | `actual` matches `expected` (value or matcher) |
| `assert.throws(fn, /regex/, [msg])` | `fn` throws and the message matches |
| `contains({ … })` | object/array contains the given subset (nestable) |
| `truthy()` / `falsy()` | value is truthy / falsy |
| `has_length(n)` / `is_type(t)` / `regex(/…/)` / `pred(fn)` | length / type / regex / predicate matches |

Structure tests with `describe` / `it`; property-based tests with
`prop(name, gen.…, (value) => { … })`.
