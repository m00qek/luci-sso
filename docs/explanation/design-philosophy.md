# About the Design Philosophy

`luci-sso` is built around a small set of principles that reflect the constraints of its environment: a security-critical authentication plugin running on resource-constrained embedded hardware, where failures have real consequences. This page explains those principles and why they exist. The rules that put them into practice are in the [Style Guide](../reference/style-guide.md#design-rules).

---

## Core Tenets

1. **Security First** — Authentication code has to be paranoid. When in doubt it fails closed, and it never assumes external input is benign.
2. **Minimal Dependencies** — The plugin has to fit within what an OpenWrt router offers: little RAM and flash, and no Python, Node.js or Go runtime. Every dependency is a liability.
3. **Testability** — All logic can be tested offline, without a real IdP and without a real network. On a router, where the suite can't run against live services, this is what makes confident change possible.
4. **OpenWrt Native** — The project follows OpenWrt and ucode conventions. It is not a Node.js project, even though ucode looks like JavaScript.
5. **Explicit Over Implicit** — Code should be obvious to a reader, not clever. An auditor should be able to follow a login from request to session without guessing.

---

## Architecture Principles

### I/O arrives through `deps`

Network requests, filesystem access, ubus, UCI, timestamps, randomness and logging all reach a module through one injected object, `deps`, instead of being called directly. [About the Architecture](architecture.md#all-io-goes-through-deps) describes what each field is in production.

The alternative, calling `uclient`, `time()` or the filesystem directly, would make the code untestable where it matters most. OpenWrt routers can't run network tests, so every external call has to be something a test can replace. With `deps`, a test hands a module a fake environment and the module cannot tell the difference. Because the fake reaches everything the module imports, the same mechanism tests a single wrapper or the whole login flow; [About the Test Architecture](test-architecture.md) follows that thread.

The line between what goes in `deps` and what doesn't is determinism. Anything external or non-deterministic belongs there. Pure transformations such as string handling, Base64URL, JSON and URL normalisation don't, because a test gains nothing by faking them. Logging is in `deps` too: a security-critical service must always be able to say what it did, and a test must be able to see that it did.

---

### Security invariants live in code, not UCI

Configuration has two dimensions: UCI, which the administrator controls, and code, which is fixed at build time. Security invariants, such as the list of allowed ID Token algorithms (`ALLOWED_ALGS` in `oidc.uc`), are constants in code. They are not UCI options and not function parameters.

Anything configurable can be misconfigured, and anything passed in can be passed in wrong. If the algorithm list were an option, a careless edit, or an attacker able to change the configuration, could re-enable `HS256` and open the door to algorithm confusion, where a token signed with a shared secret is accepted as if the IdP had signed it with its private key. Keeping the invariant in code means neither a router's configuration nor a caller can weaken it.

---

### Minimal C code

Cryptographic primitives belong in C, delegated to a crypto library (mbedTLS, wolfSSL or OpenSSL). Everything else (business logic, state machines, role mapping, string parsing) belongs in ucode.

C code is harder to audit, harder to test, and harder to port. A memory-safety bug in C is a vulnerability; the same mistake in ucode is an error message. So the C layer is kept to what ucode cannot do: cryptography backed by a vetted library.

---

### Swappable crypto backends

Routers differ in which crypto library they already carry, and flash is scarce, so `luci-sso` is built once per library. Every backend package installs its build under the same name, `luci_sso/native.so`, so `luci_sso.native` always means whichever backend is installed. [About Crypto Backends](crypto-backends.md) compares them.

That only works if no code depends on a particular backend. `deps.uc` is the one module that imports `luci_sso.native`; everything else receives it as `deps.native`, and the crypto wrappers take it as an argument. The same choice is what lets the crypto wrapper tests replace `native` with a fake.

---

## Error Handling Philosophy

Two kinds of failure exist in this codebase, and they are handled differently.

**Contract bugs** are programming errors: a function called with the wrong types, or in an invalid state. They are bugs in the calling code, and the code stops on them with `die()`. Crashing fast prevents undefined behaviour and makes the bug immediately visible, instead of letting a wrong value travel further into an authentication decision.

**Runtime realities** are expected failures: an expired token, a network outage, an invalid signature, a malformed response from the IdP. They are valid states the application has to handle, so they are returned as `Result` objects that the caller inspects.

The reason not to throw everywhere is the CGI environment. An unhandled exception produces a generic 500 error with nothing useful in it. An explicit `Result` error carries a code the web layer can turn into a meaningful HTTP status, and a log line an administrator can act on; [Log Messages](../reference/log-messages.md) lists them. The [Style Guide](../reference/style-guide.md#error-handling) has the rules and the decision tree.
