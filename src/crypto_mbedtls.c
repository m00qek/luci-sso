#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

/**
 * Verifies an RS256 signature.
 * @param msg The raw message string.
 * @param sig The raw binary signature (decoded from base64).
 * @param key The PEM public key.
 */
static uc_value_t *uc_mbedtls_verify_rs256(uc_vm_t *vm, size_t nargs) {
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

    // 1. Hash the message
    unsigned char hash[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, msg, msg_len);
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    // 2. Parse public key
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, strlen(key_pem) + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    // 3. Verify signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len);
    
    mbedtls_pk_free(&pk);

    return ucv_boolean_new(ret == 0);
}

static const uc_function_list_t mbedtls_fns[] = {
    { "verify_rs256", uc_mbedtls_verify_rs256 },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
    uc_function_list_register(scope, mbedtls_fns);
}