# Testing Architecture

`luci-sso` uses a five-tier testing strategy organized by scope, moving from low-level crypto to full system simulation.

---

## Tier Overview

| Tier | Scope | Target |
| :--- | :--- | :--- |
| **Tier 0** | Native Backend | Cryptographic primitives (SHA, HMAC, ECC) and memory safety in C. |
| **Tier 1** | Crypto Plumbing | Low-level ucode logic and constant-time comparisons. |
| **Tier 2** | Business Logic | OIDC state machines, role mapping, and configuration parsing. |
| **Tier 3** | Integration | Full system simulation (CGI headers, UBUS, I/O) using mocks. |
| **Tier 4** | Framework | Self-tests for the testing library itself. |

Tests live in `test/tier*/`. Run all tiers with `make -C devenv test` (requires `make -C devenv infra-up DOCKER_SUITE=ci` first — see [Running Tests](../how-to/developer/testing.md)).

---

## Writing Tests

Tests use a custom mocking library (`test/mock.uc`) to simulate the OpenWrt environment (filesystem, network, UBUS) without requiring real hardware or network access.

### Basic Mock Example

```javascript
import * as mock from 'mock';

let factory = mock.create();

factory.with_files({ "/etc/config/luci-sso": "..." }, (io) => {
    let config = load_config(io);
    assert_eq(config.enabled, 1);
});
```

### Verifying Side-Effects (Spying)

```javascript
let data = factory.with_ubus({ "session:destroy": {} }).spy((io) => {
    perform_logout(io);
});

assert(data.called("ubus", "session", "destroy"));
assert(data.called("log", "warn"));
```

---

## Test Requirements

| Requirement | Rule |
| :--- | :--- |
| **Coverage** | Every exported function MUST have unit tests. |
| **Error paths** | Every error path MUST be verified by a corresponding test case. |
| **Attack simulation** | Security-critical code MUST include attack tests (tampered token, alg confusion, replay). |
| **Offline purity** | All tests MUST run offline without external network dependencies. |

---

## Test Naming

**Pattern:** `test('Module: Feature - Condition', () => { ... })`

```javascript
test('JWT: Verify RS256 signature', () => { /* ... */ });
test('JWT: Reject expired token', () => { /* ... */ });
test('Security: Reject alg=none attack', () => { /* ... */ });
```

---

## Minimum Coverage Per Function

- 1 success case (happy path)
- 1 error case per error type
- Edge cases (empty input, null, boundary values)
- Security cases (tampering, injection, bypass attempts)
