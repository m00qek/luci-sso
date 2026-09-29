# How to Run the Fuzzer

This guide describes how to use the coverage-guided fuzzer (**libFuzzer** + **AddressSanitizer**) to test native C components against malformed inputs. For context on why fuzzing is required for new C code, see the [Security Model](../../explanation/security-model.md).

## What is fuzzed

The harness, `test/fuzz_test.c`, calls the guarded entry points in `mod/native_api.c`: the same functions the ucode binding calls. Each fuzz binary is the harness, `native_api.c` and one backend, so the input guards run exactly as in production, and the backend sees only inputs production could hand it.

Byte 0 of each input selects one of six targets: `jwk_rsa_to_pem`, `jwk_ec_p256_to_pem`, `verify_rs256`, `verify_es256`, `sha256` and `hmac_sha256`. The rest of the input is split into fields by big-endian 16-bit length prefixes. Besides ASan's memory checks, the harness aborts if a PEM conversion reports success without a NUL-terminated result, since the ucode binding treats that buffer as a C string.

`random` is not fuzzed: it takes only a length, which `test/native` covers at its bounds.

---

## Running the Fuzzer

The fuzzer runs in a specialized container with the Clang/LLVM toolchain.

### 1. Run for a specific backend
You must specify which crypto library you want to fuzz (mbedtls, openssl, or wolfssl).

```bash
# Run for 60 seconds (default)
make fuzzer-test CRYPTO_LIB=mbedtls
```

### 2. Custom Duration
For deep-dive discovery, you can increase the fuzzing time:

```bash
# Run for 10 minutes
make fuzzer-test CRYPTO_LIB=openssl TIME=600

# Enable leak detection (disabled by default to speed up initial discovery)
make fuzzer-test CRYPTO_LIB=mbedtls DETECT_LEAKS=1
```

## Analyzing Crashes
If the fuzzer finds a bug, it will stop and save a "crash-*" file in the `bin/fuzz/` directory.

1.  **Read the Logs:** ASan will output a stack trace identifying the exact line of C code where the memory violation occurred.
2.  **Reproduce:** The "crash-*" file contains the binary input that caused the crash. You can feed this back into the fuzzer to confirm the fix.

---

## Security Mandate
All new native C code handling external buffers **MUST** be fuzzed before it is merged into `main`.
