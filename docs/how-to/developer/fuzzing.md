# How to Run the Fuzzer

This guide describes how to use the coverage-guided fuzzer (**libFuzzer** + **AddressSanitizer**) to test native C components against malformed inputs. For context on why fuzzing is required for new C code, see the [Security Model](../../explanation/security-model.md).

---

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
