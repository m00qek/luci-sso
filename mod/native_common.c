#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ucode/module.h>
#include "native.h"

#define VALIDATE_INPUT_SIZES(msg_len, sig_len, key_len) \
	do { \
		if ((msg_len) > NATIVE_MAX_INPUT_SIZE || (sig_len) > NATIVE_MAX_INPUT_SIZE || (key_len) > NATIVE_MAX_INPUT_SIZE) { \
			return ucv_boolean_new(false); \
		} \
	} while(0)

#define VALIDATE_INPUT_SIZES_NULL(msg_len, sig_len, key_len) \
	do { \
		if ((msg_len) > NATIVE_MAX_INPUT_SIZE || (sig_len) > NATIVE_MAX_INPUT_SIZE || (key_len) > NATIVE_MAX_INPUT_SIZE) { \
			return NULL; \
		} \
	} while(0)

static uc_value_t *uc_native_verify_rs256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_msg = uc_fn_arg(0);
    uc_value_t *v_sig = uc_fn_arg(1);
    uc_value_t *v_key = uc_fn_arg(2);

    if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
        return ucv_boolean_new(false);
    }

    const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
    size_t msg_len = ucv_string_length(v_msg);
    const unsigned char *sig = (const unsigned char *)ucv_string_get(v_sig);
    size_t sig_len = ucv_string_length(v_sig);
    const char *key_pem = ucv_string_get(v_key);
    size_t key_len = ucv_string_length(v_key);

    VALIDATE_INPUT_SIZES(msg_len, sig_len, key_len);

    return ucv_boolean_new(native_verify_rs256(msg, msg_len, sig, sig_len, key_pem, key_len));
}

static uc_value_t *uc_native_verify_es256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_msg = uc_fn_arg(0);
    uc_value_t *v_sig = uc_fn_arg(1);
    uc_value_t *v_key = uc_fn_arg(2);

    if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
        return ucv_boolean_new(false);
    }

    const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
    size_t msg_len = ucv_string_length(v_msg);
    const unsigned char *sig = (const unsigned char *)ucv_string_get(v_sig);
    size_t sig_len = ucv_string_length(v_sig);
    const char *key_pem = ucv_string_get(v_key);
    size_t key_len = ucv_string_length(v_key);

    VALIDATE_INPUT_SIZES(msg_len, sig_len, key_len);

    /* Protocol validation: ES256 signatures (ECDSA P-256) MUST be 64 bytes (R|S) */
    if (sig_len != NATIVE_ES256_SIG_SIZE) return ucv_boolean_new(false);

    return ucv_boolean_new(native_verify_es256(msg, msg_len, sig, sig_len, key_pem, key_len));
}

static uc_value_t *uc_native_sha256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;

    const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
    size_t input_len = ucv_string_length(arg);

    VALIDATE_INPUT_SIZES_NULL(input_len, 0, 0);

    unsigned char output[NATIVE_SHA256_SIZE];
    if (native_sha256(input, input_len, output) != 0) return NULL;

    return ucv_string_new_length((const char *)output, NATIVE_SHA256_SIZE);
}

static uc_value_t *uc_native_hmac_sha256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_key = uc_fn_arg(0);
    uc_value_t *v_msg = uc_fn_arg(1);

    if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) return NULL;

    const unsigned char *key = (const unsigned char *)ucv_string_get(v_key);
    size_t key_len = ucv_string_length(v_key);
    const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
    size_t msg_len = ucv_string_length(v_msg);

    /* Security: an empty key means the caller lost its secret somewhere upstream.
     * HMAC is defined for a zero-length key, so the backends disagree here:
     * mbedtls' PSA refuses it, while wolfSSL's wc_HmacSetKey and OpenSSL's
     * EVP_MAC accept it and return a MAC computed with no secret at all. Reject
     * it here so every backend fails loudly rather than two of three silently
     * authenticating with nothing. */
    if (key_len == 0) return NULL;

    VALIDATE_INPUT_SIZES_NULL(msg_len, 0, key_len);

    unsigned char mac[NATIVE_SHA256_SIZE];
    if (native_hmac_sha256(key, key_len, msg, msg_len, mac) != 0) {
        native_memzero(mac, sizeof(mac));
        return NULL;
    }

    uc_value_t *res = ucv_string_new_length((const char *)mac, NATIVE_SHA256_SIZE);
    native_memzero(mac, sizeof(mac));
    return res;
}

static uc_value_t *uc_native_random(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    int len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;
    if (len <= 0 || len > 4096) return NULL;

    unsigned char *buf = malloc(len);
    if (!buf) return NULL;

    if (native_random(buf, len) != 0) {
        free(buf);
        return NULL;
    }

    uc_value_t *res = ucv_string_new_length((const char *)buf, len);
    native_memzero(buf, len);
    free(buf);
    return res;
}

static uc_value_t *uc_native_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_n = uc_fn_arg(0);
    uc_value_t *v_e = uc_fn_arg(1);

    if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

    const unsigned char *n = (const unsigned char *)ucv_string_get(v_n);
    size_t n_len = ucv_string_length(v_n);
    const unsigned char *e = (const unsigned char *)ucv_string_get(v_e);
    size_t e_len = ucv_string_length(v_e);

    /* Security: the modulus is attacker-supplied (it arrives in a JWKS document),
     * so it needs the same 16 KB ceiling as every other input. This check was
     * missing: mbedtls happened to reject an oversized modulus during key import,
     * but wolfSSL and OpenSSL did not, so the ceiling was never actually enforced. */
    VALIDATE_INPUT_SIZES_NULL(n_len, 0, e_len);

    /* Security: Reject exponents that are: Empty, Even, or Not exactly 65537 (RFC 4871) 
     * We only support the standard F4 exponent (0x010001) for safety and simplicity. */
    if (e_len != 3 || e[0] != 0x01 || e[1] != 0x00 || e[2] != 0x01) return NULL;

    char pem[NATIVE_RSA_PEM_MAX];
    if (native_jwk_rsa_to_pem(n, n_len, e, e_len, pem, sizeof(pem)) != 0) return NULL;

    return ucv_string_new(pem);
}

static uc_value_t *uc_native_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_x = uc_fn_arg(0);
    uc_value_t *v_y = uc_fn_arg(1);

    if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

    const unsigned char *x = (const unsigned char *)ucv_string_get(v_x);
    size_t x_len = ucv_string_length(v_x);
    const unsigned char *y = (const unsigned char *)ucv_string_get(v_y);
    size_t y_len = ucv_string_length(v_y);

    /* Enforce P-256 coordinate lengths (32 bytes each) */
    if (x_len != NATIVE_EC_COORD_SIZE || y_len != NATIVE_EC_COORD_SIZE) return NULL;

    char pem[NATIVE_EC_PEM_MAX];
    if (native_jwk_ec_p256_to_pem(x, x_len, y, y_len, pem, sizeof(pem)) != 0) return NULL;

    return ucv_string_new(pem);
}

static const uc_function_list_t native_fns[] = {
    { "verify_rs256", uc_native_verify_rs256 },
    { "verify_es256", uc_native_verify_es256 },
    { "sha256", uc_native_sha256 },
    { "hmac_sha256", uc_native_hmac_sha256 },
    { "random", uc_native_random },
    { "jwk_rsa_to_pem", uc_native_jwk_rsa_to_pem },
    { "jwk_ec_p256_to_pem", uc_native_jwk_ec_p256_to_pem },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
    if (native_crypto_init() == 0) {
        uc_function_list_register(scope, native_fns);
    }
}
