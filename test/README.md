# Tests

Unit tests, integration tests, and fuzz tests for `luci-sso`.

For architecture details and writing guidance, see [Testing Architecture](https://m00qek.github.io/luci-sso/reference/testing-architecture/) and [How to Run Tests](https://m00qek.github.io/luci-sso/how-to/developer/testing/).

---

## Running tests

```bash
make unit-test                          # All tiers
make unit-test VERBOSE=1                # With per-test output
make unit-test FILTER='compliance.*SHA' # Regex filter on test names
make unit-test MODULES='test/tier2/oidc_logic_test.uc'  # Specific file

make up && make e2e-test      # Full E2E (requires Docker)
make -sC devenv fuzzer-test CRYPTO_LIB=mbedtls  # Fuzz (60s)
```

## Tier overview

| Tier | Directory | What it tests |
| :--- | :--- | :--- |
| 0 | `tier0/` | Native C crypto primitives, memory safety |
| 1 | `tier1/` | ucode crypto layer, constant-time comparisons |
| 2 | `tier2/` | Business logic — OIDC state machine, role mapping, config |
| 3 | `tier3/` | Integration — CGI headers, UBUS session management |
| 4 | `tier4/` | Framework self-tests |

---

## Mock DSL quick reference

```javascript
import * as mock from 'mock';

let factory = mock.create();

// Basic: set environment variables, get an io object
factory.with_env({ PATH_INFO: "/callback" }, (io) => {
    let req = web.request(io);
});

// Files: raw strings or metadata objects
factory.with_files({
    "/etc/config/luci-sso": "config oidc 'default'\n...",
    "/etc/stale.lock": { ".type": "directory", ".mtime": 1516230000 },
}, (io) => {
    let st = io.stat("/etc/stale.lock");
});

// Network: stub HTTP responses
factory.with_responses({
    "https://idp/.well-known/openid-configuration": { issuer: "https://idp" }
}, (io) => { ... });

// Chaining: accumulate state across calls
factory.with_files({ "/etc/key": "abc" }, (io) => {
    factory.using(io).with_responses({ "https://idp/jwks": {...} }).spy((io2) => {
        router.handle(io2, ...);
    });
});

// Spying: verify side-effects after execution
let data = factory.with_ubus({ "session:destroy": {} }).spy((io) => {
    router.handle(io, ...);
});
assert(data.called("ubus", "session", "destroy"));
assert(data.called("log", "warn"));
```

## Assertions

| Function | Passes when |
| :--- | :--- |
| `assert(cond, [msg])` | `cond` is truthy |
| `assert_eq(actual, expected, [msg])` | deep equality |
| `assert_match(actual, regex, [msg])` | string matches regex |
| `assert_throws(fn, [msg])` | `fn` throws |
| `assert_fail([msg])` | never — unconditional failure |
