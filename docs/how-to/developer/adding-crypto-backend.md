# How to Add a New Crypto Backend

`luci-sso` supports multiple cryptographic backends via a native C bridge. This allows the project to use whatever library is already available on the target OpenWrt device (MbedTLS, wolfSSL, or OpenSSL).

Use this guide if you need to implement a new backend provider, such as for BoringSSL or a hardware-specific crypto library.

---

## Implement the Interface

The native module has three layers, all in `mod/`:

| File | Role |
| :--- | :--- |
| `native_ucode.c` | ucode binding: checks argument types and converts values. Makes no security decisions. |
| `native_api.c` | Guarded entry points: every input check (size ceilings, exact lengths, the RSA exponent allow-list, the empty-HMAC-key rejection, output termination) lives here, then calls the backend. |
| `native_<lib>.c` | Backend: implements `native.h` for one crypto library. |

A new backend is only the third layer. Create `mod/native_boringssl.c` and implement the functions declared in `mod/native.h`. It inherits every guard in `native_api.c` without writing any of them.

Your implementation **MUST** fulfill these security requirements:

| Function | Security Requirement |
| :--- | :--- |
| `native_verify_rs256` | Reject RSA keys smaller than 2048 bits. |
| `native_verify_es256` | Verify with the library's ECDSA P-256 routine, taking the signature as 64 bytes of `R` followed by `S`. Never compare signature bytes yourself. |
| `native_random` | Must use a cryptographically secure random number generator (CSPRNG). |
| `native_memzero` | Must use a compiler-safe zeroization function (e.g., `explicit_bzero`) to prevent optimization removal. |

### Handling Input Limits

`native_api.c` rejects inputs over 16 KB (`NATIVE_MAX_INPUT_SIZE`), ES256 signatures that are not exactly 64 bytes, EC coordinates that are not exactly 32 bytes, and RSA exponents other than 65537 before your code runs. Your backend **SHOULD** still validate lengths for its own internal buffers: the existing backends keep their own checks as defence in depth.

The PEM converters must write a NUL-terminated string into `out` and fail if it does not fit. `native_api.c` zero-fills the buffer and rejects an unterminated result anyway, but a backend should not rely on that.

---

## Register the Backend

Add your new backend to `mod/CMakeLists.txt`. The shared library is the binding, the guard layer and your backend, linked against your crypto library and `ucode`.

```cmake
find_library(BORINGSSL_LIB crypto)

if(BORINGSSL_LIB AND UCODE_LIB)
    add_library(native_boringssl SHARED native_ucode.c native_api.c native_boringssl.c)
    set_target_properties(native_boringssl PROPERTIES PREFIX "")
    target_link_libraries(native_boringssl ${UCODE_LIB} ${BORINGSSL_LIB})
    install(TARGETS native_boringssl DESTINATION lib/ucode)
endif()
```

---

## Verify Compliance

The `test/native` bucket exercises every export of the compiled module: known-answer tests (KAT), rejection of weak or mismatched keys, and the input guards.

1.  **Build** your new backend:
    ```bash
    make compile CRYPTO_LIB=boringssl
    ```

2.  **Run** the native bucket (and the rest of the unit suite) against it:
    ```bash
    make unit-test CRYPTO_LIB=boringssl MODULES='test/native'
    make unit-test CRYPTO_LIB=boringssl
    ```

If the compliance tests pass, the backend is correctly mapping its internal library functions to the `luci-sso` expected interface.

---

## Add a Fuzzing Target

To ensure your implementation is memory-safe when parsing IdP-provided tokens, add a fuzzer target to `mod/CMakeLists.txt`. It links the harness, the guard layer and your backend, so it fuzzes the same path production runs:

```cmake
if(ENABLE_FUZZING AND BORINGSSL_LIB)
    add_executable(fuzz_boringssl ../test/fuzz_test.c native_api.c native_boringssl.c)
    target_compile_options(fuzz_boringssl PRIVATE -fsanitize=fuzzer,address)
    target_link_libraries(fuzz_boringssl -fsanitize=fuzzer,address ${BORINGSSL_LIB})
endif()
```

Run the fuzzer to verify:
```bash
make fuzzer-test CRYPTO_LIB=boringssl
```

---

## Package for OpenWrt

To allow users to install your backend with the package manager (`opkg` on OpenWrt 24.10, `apk` on 25.12), you must add a new package definition to `openwrt/luci-sso/Makefile`.

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
