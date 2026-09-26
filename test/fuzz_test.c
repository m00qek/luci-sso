#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "native.h"
#include "native_api.h"

/**
 * libFuzzer target for the native crypto module.
 *
 * Every call goes through the guarded native_api_* entry points, the same
 * functions the ucode binding calls, so the fuzzer exercises the input
 * checks as well as the backend behind them.
 *
 * Input layout: byte 0 selects the target; the rest is the payload. Payloads
 * start with big-endian 16-bit lengths for each field, followed by the
 * fields back to back.
 */

/* Split `payload` into `count` fields whose 16-bit lengths prefix it.
 * Returns 0 and fills ptr/len when the declared fields fit. */
static int split_fields(const uint8_t *payload, size_t psize, int count,
                        const uint8_t **ptr, size_t *len) {
    size_t header = (size_t)count * 2;
    if (psize < header) return -1;

    const uint8_t *p = payload + header;
    size_t rest = psize - header;
    for (int i = 0; i < count; i++) {
        len[i] = (size_t)payload[2 * i] << 8 | payload[2 * i + 1];
        if (len[i] > rest) return -1;
        ptr[i] = p;
        p += len[i];
        rest -= len[i];
    }
    return 0;
}

/* native_api guarantees a NUL-terminated PEM on success. A violation would
 * let the ucode binding read past the buffer, so treat it as a crash. */
static void require_terminated(int rc, const char *out, size_t out_len) {
    if (rc == 0 && memchr(out, '\0', out_len) == NULL) abort();
}

/* The verifiers need the key as a C string: the backends parse PEM with the
 * terminator included, as the ucode binding provides it. */
static void verify(bool (*fn)(const unsigned char *, size_t, const unsigned char *, size_t, const char *, size_t),
                   const uint8_t **ptr, const size_t *len) {
    char *key = malloc(len[2] + 1);
    if (!key) return;
    memcpy(key, ptr[2], len[2]);
    key[len[2]] = '\0';
    fn(ptr[0], len[0], ptr[1], len[1], key, len[2]);
    free(key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    static int initialized = 0;
    if (!initialized) {
        native_crypto_init();
        atexit(native_crypto_deinit);
        initialized = 1;
    }

    const uint8_t *payload = data + 1;
    size_t psize = size - 1;
    const uint8_t *ptr[3];
    size_t len[3];

    switch (data[0] % 6) {
        case 0: { /* jwk_rsa_to_pem(n, e) */
            if (split_fields(payload, psize, 2, ptr, len) != 0) break;
            char out[NATIVE_RSA_PEM_MAX];
            int rc = native_api_jwk_rsa_to_pem(ptr[0], len[0], ptr[1], len[1], out, sizeof(out));
            require_terminated(rc, out, sizeof(out));
            break;
        }
        case 1: { /* jwk_ec_p256_to_pem(x, y) */
            if (split_fields(payload, psize, 2, ptr, len) != 0) break;
            char out[NATIVE_EC_PEM_MAX];
            int rc = native_api_jwk_ec_p256_to_pem(ptr[0], len[0], ptr[1], len[1], out, sizeof(out));
            require_terminated(rc, out, sizeof(out));
            break;
        }
        case 2: /* verify_rs256(msg, sig, key) */
            if (split_fields(payload, psize, 3, ptr, len) == 0)
                verify(native_api_verify_rs256, ptr, len);
            break;
        case 3: /* verify_es256(msg, sig, key) */
            if (split_fields(payload, psize, 3, ptr, len) == 0)
                verify(native_api_verify_es256, ptr, len);
            break;
        case 4: { /* sha256(input): the whole payload */
            unsigned char out[NATIVE_SHA256_SIZE];
            native_api_sha256(payload, psize, out);
            break;
        }
        case 5: { /* hmac_sha256(key, msg) */
            if (split_fields(payload, psize, 2, ptr, len) != 0) break;
            unsigned char out[NATIVE_SHA256_SIZE];
            native_api_hmac_sha256(ptr[0], len[0], ptr[1], len[1], out);
            break;
        }
    }

    return 0;
}
