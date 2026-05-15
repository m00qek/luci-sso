# How to Add a New Crypto Backend

`luci-sso` supports multiple cryptographic backends via a native C bridge. This allows the project to use whatever library is already available on the target OpenWrt device (MbedTLS, wolfSSL, or OpenSSL).

Use this guide if you need to implement a new backend provider, such as for BoringSSL or a hardware-specific crypto library.

---

## Implement the Interface

Create a new file in `src/` (e.g., `src/native_boringssl.c`) and implement the functions defined in `src/native.h`. 

Your implementation **MUST** fulfill these security requirements:

| Function | Security Requirement |
| :--- | :--- |
| `native_verify_rs256` | Reject RSA keys smaller than 2048 bits. |
| `native_verify_es256` | Use constant-time comparison for signature verification results. |
| `native_random` | Must use a cryptographically secure random number generator (CSPRNG). |
| `native_memzero` | Must use a compiler-safe zeroization function (e.g., `explicit_bzero`) to prevent optimization removal. |

### Handling Input Limits

All functions receive an `unsigned char *msg` and `size_t msg_len`. The calling code in `web.uc` enforces a 16 KB limit (`NATIVE_MAX_INPUT_SIZE`) before data reaches the C layer, but your backend **SHOULD** still validate lengths for internal buffers.

---

## Register the Backend

Add your new backend to `src/CMakeLists.txt`. You must create a shared library target that links against your crypto library and the `ucode` library.

```cmake
find_library(BORINGSSL_LIB crypto)

if(BORINGSSL_LIB AND UCODE_LIB)
    add_library(native_boringssl SHARED native_boringssl.c native_common.c)
    set_target_properties(native_boringssl PROPERTIES PREFIX "")
    target_link_libraries(native_boringssl ${UCODE_LIB} ${BORINGSSL_LIB})
    install(TARGETS native_boringssl DESTINATION lib/ucode)
endif()
```

---

## Verify Compliance

`luci-sso` includes a "Compliance Test" that exercises every cryptographic primitive in the backend using known-answer tests (KAT).

1.  **Register your backend for artifact extraction** in `devenv/services/sdk/build.sh`. Add `boringssl` to the loop in the `compile)` case so the built `.so` is copied alongside the existing backends:

    ```bash
    for lib in mbedtls wolfssl openssl boringssl; do
    ```

2.  **Build** all backends (including yours):
    ```bash
    make -C devenv compile
    ```

3.  **Start infrastructure** and **run** Tier 0 compliance tests:
    ```bash
    make -C devenv infra-up DOCKER_SUITE=ci
    make -C devenv test CRYPTO_LIB=boringssl FILTER=native_compliance
    make -C devenv infra-down DOCKER_SUITE=ci
    ```

If the compliance tests pass, the backend is correctly mapping its internal library functions to the `luci-sso` expected interface.

---

## Add a Fuzzing Target

To ensure your implementation is memory-safe when parsing IdP-provided tokens, add a fuzzer target to `src/CMakeLists.txt`:

```cmake
if(ENABLE_FUZZING AND BORINGSSL_LIB)
    add_executable(fuzz_boringssl ../test/fuzz_test.c native_boringssl.c)
    target_compile_options(fuzz_boringssl PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(fuzz_boringssl -fsanitize=fuzzer,address ${BORINGSSL_LIB})
endif()
```

Run the fuzzer to verify:
```bash
make -sC devenv fuzz CRYPTO_LIB=boringssl
```

---

## Package for OpenWrt

To allow users to install your backend via `opkg`, you must add a new package definition to the project's root `Makefile`.

### Define the Package
Add a new `Package/luci-sso-crypto-xxx` section. It must `PROVIDES:=luci-sso-crypto` so the main package can depend on it.

```makefile
define Package/$(PKG_NAME)-crypto-boringssl
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=BoringSSL backend for $(PKG_NAME)
  DEPENDS:=+libucode +libboringssl
  PROVIDES:=luci-sso-crypto
endef
```

### Implement the Install Macro
The install macro must copy your compiled library to `/usr/lib/ucode/luci_sso/native.so` on the target system. Note the rename to `native.so` — this is how the ucode layer remains backend-agnostic.

```makefile
define Package/$(PKG_NAME)-crypto-boringssl/install
	$(INSTALL_DIR) $(1)/usr/lib/ucode/luci_sso
	# The || true prevents a build failure when the library was not built for this architecture.
	[ -f $(PKG_INSTALL_DIR)/usr/lib/ucode/native_boringssl.so ] && \
		$(CP) $(PKG_INSTALL_DIR)/usr/lib/ucode/native_boringssl.so $(1)/usr/lib/ucode/luci_sso/native.so || true
endef
```

### Register for Build
Finally, call `BuildPackage` at the bottom of the `Makefile`:

```makefile
$(eval $(call BuildPackage,$(PKG_NAME)-crypto-boringssl))
```
