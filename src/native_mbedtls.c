#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// ... (Existing ecdsa_raw_to_der_robust) ...
static int ecdsa_raw_to_der_robust(const unsigned char *raw, size_t raw_len, 
                                 unsigned char *buf, size_t buf_len,
                                 unsigned char **out_der_ptr, size_t *out_der_len) {
    if (raw_len % 2 != 0) return -1;
    size_t coord_len = raw_len / 2;

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = 0;
    if ((ret = mbedtls_mpi_read_binary(&r, raw, coord_len)) != 0) goto cleanup;
    if ((ret = mbedtls_mpi_read_binary(&s, raw + coord_len, coord_len)) != 0) goto cleanup;

    unsigned char *p = buf + buf_len;
    size_t len = 0;

    ret = mbedtls_asn1_write_mpi(&p, buf, &s);
    if (ret < 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_mpi(&p, buf, &r);
    if (ret < 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_len(&p, buf, len);
    if (ret < 0) goto cleanup;
    len += ret;

    ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret < 0) goto cleanup;
    len += ret;

    *out_der_ptr = p;
    *out_der_len = len;
    ret = 0;

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}

// ... (Existing verify_rs256, verify_es256, sha256, random) ...
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
    size_t key_len = ucv_string_length(v_key);

    unsigned char hash[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info || mbedtls_md_setup(&md_ctx, md_info, 0) != 0 ||
        mbedtls_md_starts(&md_ctx) != 0 ||
        mbedtls_md_update(&md_ctx, msg, msg_len) != 0 ||
        mbedtls_md_finish(&md_ctx, hash) != 0) {
        mbedtls_md_free(&md_ctx);
        return ucv_boolean_new(false);
    }
    mbedtls_md_free(&md_ctx);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, sig, sig_len);
    mbedtls_pk_free(&pk);
    return ucv_boolean_new(ret == 0);
}

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
    size_t key_len = ucv_string_length(v_key);

    if (raw_sig_len != 64) return ucv_boolean_new(false);

    unsigned char der_buf[128]; 
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;

    if (ecdsa_raw_to_der_robust(raw_sig, raw_sig_len, der_buf, sizeof(der_buf), &der_sig, &der_sig_len) != 0) {
        return ucv_boolean_new(false);
    }

    unsigned char hash[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info || mbedtls_md_setup(&md_ctx, md_info, 0) != 0 ||
        mbedtls_md_starts(&md_ctx) != 0 ||
        mbedtls_md_update(&md_ctx, msg, msg_len) != 0 ||
        mbedtls_md_finish(&md_ctx, hash) != 0) {
        mbedtls_md_free(&md_ctx);
        return ucv_boolean_new(false);
    }
    mbedtls_md_free(&md_ctx);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        mbedtls_pk_free(&pk);
        return ucv_boolean_new(false);
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, der_sig, der_sig_len);
    mbedtls_pk_free(&pk);
    return ucv_boolean_new(ret == 0);
}

static uc_value_t *uc_mbedtls_sha256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    if (ucv_type(arg) != UC_STRING) return NULL;
    const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
    size_t input_len = ucv_string_length(arg);
    unsigned char output[32];
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info || mbedtls_md_setup(&md_ctx, md_info, 0) != 0 ||
        mbedtls_md_starts(&md_ctx) != 0 ||
        mbedtls_md_update(&md_ctx, input, input_len) != 0 ||
        mbedtls_md_finish(&md_ctx, output) != 0) {
        mbedtls_md_free(&md_ctx);
        return NULL;
    }
    mbedtls_md_free(&md_ctx);
    return ucv_string_new_length((const char *)output, 32);
}

static mbedtls_entropy_context global_entropy;
static mbedtls_ctr_drbg_context global_ctr_drbg;
static int drbg_initialized = 0;

static uc_value_t *uc_mbedtls_random(uc_vm_t *vm, size_t nargs) {
    uc_value_t *arg = uc_fn_arg(0);
    int len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;
    if (len <= 0 || len > 4096) return NULL;

    if (!drbg_initialized) {
        const char *pers = "ucode_mbedtls_persistent";
        mbedtls_entropy_init(&global_entropy);
        mbedtls_ctr_drbg_init(&global_ctr_drbg);
        int ret = mbedtls_ctr_drbg_seed(&global_ctr_drbg, mbedtls_entropy_func, &global_entropy, 
                                        (const unsigned char *)pers, strlen(pers));
        if (ret != 0) return NULL;
        drbg_initialized = 1;
    }

    unsigned char *buf = malloc(len);
    if (!buf) return NULL;

    int ret = mbedtls_ctr_drbg_random(&global_ctr_drbg, buf, len);
    if (ret != 0) {
        free(buf);
        return NULL;
    }

    uc_value_t *res = ucv_string_new_length((const char *)buf, len);
    free(buf);
    return res;
}

/**
 * Converts RSA n, e to PEM string.
 * Arguments: (n_bin, e_bin)
 */
static uc_value_t *uc_mbedtls_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_n = uc_fn_arg(0);
    uc_value_t *v_e = uc_fn_arg(1);

    if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

    const unsigned char *n = (const unsigned char *)ucv_string_get(v_n);
    size_t n_len = ucv_string_length(v_n);
    const unsigned char *e = (const unsigned char *)ucv_string_get(v_e);
    size_t e_len = ucv_string_length(v_e);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    // Setup as RSA
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    
    // Security: Reject exponents that are:
    // 1. Empty
    // 2. Even (mathematically invalid for RSA)
    // 3. Less than 3
    if (e_len == 0 || (e[e_len - 1] & 1) == 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }
    if (e_len == 1 && e[0] < 3) {
        mbedtls_pk_free(&pk);
        return NULL;
    }

    // mbedtls_rsa_import_raw is available in mbedtls 2.x/3.x
    // It imports N, P, Q, D, E. We only have N, E.
    if (mbedtls_rsa_import_raw(rsa, n, n_len, NULL, 0, NULL, 0, NULL, 0, e, e_len) != 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }
    
    // We only have Public Key components, so complete check might fail, but let's try writing.
    
    // 4096 bits = 512 bytes. PEM encoding overhead ~33%. 1024 bytes is enough.
    unsigned char buf[2048]; 
    memset(buf, 0, sizeof(buf));
    
    int ret = mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf));
    mbedtls_pk_free(&pk);

    if (ret != 0) return NULL;

    return ucv_string_new((const char *)buf);
}

/**
 * Converts ES256 (P-256) x, y to PEM string.
 * Arguments: (x_bin, y_bin)
 */
static uc_value_t *uc_mbedtls_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_x = uc_fn_arg(0);
    uc_value_t *v_y = uc_fn_arg(1);

    if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

    const unsigned char *x = (const unsigned char *)ucv_string_get(v_x);
    size_t x_len = ucv_string_length(v_x);
    const unsigned char *y = (const unsigned char *)ucv_string_get(v_y);
    size_t y_len = ucv_string_length(v_y);

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Setup as ECKEY
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }

    // Configure group P-256 (SECP256R1)
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
    if (mbedtls_ecp_group_load(&ec->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1) != 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }

    // Import Point
    // format 0x04 (uncompressed) + X + Y
    if (x_len != 32 || y_len != 32) { // P-256 coordinate must be 32 bytes
        mbedtls_pk_free(&pk);
        return NULL;
    }

    unsigned char point[65];
    point[0] = 0x04;
    memcpy(point + 1, x, 32);
    memcpy(point + 33, y, 32);

    if (mbedtls_ecp_point_read_binary(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q), point, 65) != 0) {
        mbedtls_pk_free(&pk);
        return NULL;
    }

    unsigned char buf[1024];
    memset(buf, 0, sizeof(buf));

    int ret = mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf));
    mbedtls_pk_free(&pk);

    if (ret != 0) return NULL;

    return ucv_string_new((const char *)buf);
}

static uc_value_t *uc_mbedtls_hmac_sha256(uc_vm_t *vm, size_t nargs) {
    uc_value_t *v_key = uc_fn_arg(0);
    uc_value_t *v_msg = uc_fn_arg(1);

    if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) {
        return NULL;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char mac[MBEDTLS_MD_MAX_SIZE];
    
    int ret = mbedtls_md_hmac(md_info, 
        (const unsigned char *)ucv_string_get(v_key), ucv_string_length(v_key),
        (const unsigned char *)ucv_string_get(v_msg), ucv_string_length(v_msg),
        mac);

    if (ret != 0) return NULL;

    return ucv_string_new_length((const char *)mac, mbedtls_md_get_size(md_info));
}

static const uc_function_list_t mbedtls_fns[] = {
    { "verify_rs256", uc_mbedtls_verify_rs256 },
    { "verify_es256", uc_mbedtls_verify_es256 },
    { "sha256", uc_mbedtls_sha256 },
    { "hmac_sha256", uc_mbedtls_hmac_sha256 },
    { "random", uc_mbedtls_random },
    { "jwk_rsa_to_pem", uc_mbedtls_jwk_rsa_to_pem },
    { "jwk_ec_p256_to_pem", uc_mbedtls_jwk_ec_p256_to_pem },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
    uc_function_list_register(scope, mbedtls_fns);
}