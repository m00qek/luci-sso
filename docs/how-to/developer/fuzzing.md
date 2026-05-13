# Fuzz Testing

This guide describes how to use the coverage-guided fuzzer to harden native C components.

---

## 🧠 Why Fuzz?
OIDC handshakes involve parsing untrusted data (JWTs, JWKs, Signatures). We use **libFuzzer** and **AddressSanitizer (ASan)** to identify buffer overflows, use-after-free, and other memory safety issues that standard unit tests might miss.

## 🚀 Running the Fuzzer

The fuzzer runs in a specialized container with the Clang/LLVM toolchain.

### 1. Run for a specific backend
You must specify which crypto library you want to fuzz (mbedtls, openssl, or wolfssl).

```bash
# Run for 60 seconds (default)
make -C devenv fuzzer-test CRYPTO_LIB=mbedtls
```

### 2. Custom Duration
For deep-dive discovery, you can increase the fuzzing time:

```bash
# Run for 10 minutes
make -C devenv fuzzer-test CRYPTO_LIB=openssl TIME=600
```

## 🔍 Analyzing Crashes
If the fuzzer finds a bug, it will stop and save a "crash-*" file in the `bin/fuzz/` directory.

1.  **Read the Logs:** ASan will output a stack trace identifying the exact line of C code where the memory violation occurred.
2.  **Reproduce:** The "crash-*" file contains the binary input that caused the crash. You can feed this back into the fuzzer to confirm the fix.

---

## 🛡️ Security Mandate
All new native C code handling external buffers **MUST** be fuzzed before it is merged into `main`.
