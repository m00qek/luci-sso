#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/**
 * Converts raw (r, s) signature to ASN.1 DER using mbedtls native writers.
 * Writes to the provided stack buffer (backward).
 */
static int ecdsa_raw_to_der_robust(const unsigned char *raw, size_t raw_len, 
                                 unsigned char *buf, size_t buf_len,
                                 unsigned char **out_der_ptr, size_t *out_der_len) {
    if (raw_len % 2 != 0) return -1;
    size_t coord_len = raw_len / 2;

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = 0;
    
    // 1. Read Raw R and S into MPIs
    if ((ret = mbedtls_mpi_read_binary(&r, raw, coord_len)) != 0) goto cleanup;
    if ((ret = mbedtls_mpi_read_binary(&s, raw + coord_len, coord_len)) != 0) goto cleanup;

    // 2. Write ASN.1 DER (Backwards)
    unsigned char *p = buf + buf_len;
    size_t len = 0;

    // Write S
    ret = mbedtls_asn1_write_mpi(&p, buf, &s);
    if (ret < 0) goto cleanup;
    len += ret;

    // Write R
    ret = mbedtls_asn1_write_mpi(&p, buf, &r);
    if (ret < 0) goto cleanup;
    len += ret;

    // Write SEQUENCE length
    ret = mbedtls_asn1_write_len(&p, buf, len);
    if (ret < 0) goto cleanup;
    len += ret;

    // Write SEQUENCE tag
    ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret < 0) goto cleanup;
    len += ret;

    // Success
    *out_der_ptr = p;
    *out_der_len = len;
    ret = 0;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

/**
 * Verifies an RS256 signature.
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

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, msg, msg_len);
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, strlen(key_pem) + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len);
    
    mbedtls_pk_free(&pk);

    return ucv_boolean_new(ret == 0);
}

/**
 * Verifies an ES256 signature.
 */
static uc_value_t *uc_mbedtls_verify_es256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_msg = uc_fn_arg(0);
    uc_value_t *v_sig = uc_fn_arg(1);
    uc_value_t *v_key = uc_fn_arg(2);

    if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
        return ucv_boolean_new(false);
    }

    const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
    size_t msg_len = ucv_string_length(v_msg);
    const unsigned char *raw_sig = (const unsigned char *)ucv_string_get(v_sig);
    size_t raw_sig_len = ucv_string_length(v_sig);
    const char *key_pem = ucv_string_get(v_key);

    if (raw_sig_len != 64) return ucv_boolean_new(false);

    unsigned char der_buf[128]; 
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;

    if (ecdsa_raw_to_der_robust(raw_sig, raw_sig_len, der_buf, sizeof(der_buf), &der_sig, &der_sig_len) != 0) {
        return ucv_boolean_new(false);
    }

    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, msg, msg_len);
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, strlen(key_pem) + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, der_sig, der_sig_len);
    
    mbedtls_pk_free(&pk);

    return ucv_boolean_new(ret == 0);
}

/**
 * Calculates SHA-256 hash of input.
 */
static uc_value_t *uc_mbedtls_sha256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;

    const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
    size_t input_len = ucv_string_length(arg);
    
    unsigned char output[32];
    
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, input, input_len);
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);

    return ucv_string_new_length((const char *)output, 32);
}

/**
 * Generates random bytes.
 */
static uc_value_t *uc_mbedtls_random(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    int len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;
    if (len <= 0 || len > 4096) return NULL;

    unsigned char *buf = malloc(len);
    if (!buf) return NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ucode_mbedtls";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        free(buf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return NULL;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret != 0) {
        free(buf);
        return NULL;
    }

    uc_value_t *res = ucv_string_new_length((const char *)buf, len);
    free(buf);
    return res;
}

static const uc_function_list_t mbedtls_fns[] = {
    { "verify_rs256", uc_mbedtls_verify_rs256 },
    { "verify_es256", uc_mbedtls_verify_es256 },
    { "sha256", uc_mbedtls_sha256 },
    { "random", uc_mbedtls_random },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
    uc_function_list_register(scope, mbedtls_fns);
}