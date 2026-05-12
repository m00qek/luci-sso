#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "native.h"

/**
 * libFuzzer target for native cryptographic functions.
 * Targets parsing and verification logic which handles untrusted input.
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Initialize crypto backend once
    static int initialized = 0;
    if (!initialized) {
        native_crypto_init();
        atexit(native_crypto_deinit);
        initialized = 1;
    }

    uint8_t target = data[0];
    const uint8_t *payload = data + 1;
    size_t psize = size - 1;

    switch (target % 4) {
        case 0: {
            // Target: native_jwk_rsa_to_pem
            if (psize < 4) break;
            size_t n_len = payload[0] << 8 | payload[1];
            size_t e_len = payload[2] << 8 | payload[3];
            const uint8_t *remaining = payload + 4;
            size_t rsize = psize - 4;

            if (n_len + e_len <= rsize) {
                char out[NATIVE_RSA_PEM_MAX];
                native_jwk_rsa_to_pem(remaining, n_len, remaining + n_len, e_len, out, sizeof(out));
            }
            break;
        }
        case 1: {
            // Target: native_jwk_ec_p256_to_pem
            if (psize < 4) break;
            size_t x_len = payload[0] << 8 | payload[1];
            size_t y_len = payload[2] << 8 | payload[3];
            const uint8_t *remaining = payload + 4;
            size_t rsize = psize - 4;

            if (x_len + y_len <= rsize) {
                char out[NATIVE_EC_PEM_MAX];
                native_jwk_ec_p256_to_pem(remaining, x_len, remaining + x_len, y_len, out, sizeof(out));
            }
            break;
        }
        case 2: {
            // Target: native_verify_rs256
            if (psize < 6) break;
            size_t msg_len = payload[0] << 8 | payload[1];
            size_t sig_len = payload[2] << 8 | payload[3];
            size_t key_len = payload[4] << 8 | payload[5];
            const uint8_t *remaining = payload + 6;
            size_t rsize = psize - 6;

            if (msg_len + sig_len + key_len <= rsize) {
                // Ensure key is null-terminated for mbedtls
                char *key = malloc(key_len + 1);
                if (key) {
                    memcpy(key, remaining + msg_len + sig_len, key_len);
                    key[key_len] = '\0';
                    native_verify_rs256(remaining, msg_len, remaining + msg_len, sig_len, key, key_len);
                    free(key);
                }
            }
            break;
        }
        case 3: {
            // Target: native_verify_es256
            if (psize < 6) break;
            size_t msg_len = payload[0] << 8 | payload[1];
            size_t sig_len = payload[2] << 8 | payload[3];
            size_t key_len = payload[4] << 8 | payload[5];
            const uint8_t *remaining = payload + 6;
            size_t rsize = psize - 6;

            if (msg_len + sig_len + key_len <= rsize) {
                // Ensure key is null-terminated for mbedtls
                char *key = malloc(key_len + 1);
                if (key) {
                    memcpy(key, remaining + msg_len + sig_len, key_len);
                    key[key_len] = '\0';
                    native_verify_es256(remaining, msg_len, remaining + msg_len, sig_len, key, key_len);
                    free(key);
                }
            }
            break;
        }
    }

    return 0;
}
