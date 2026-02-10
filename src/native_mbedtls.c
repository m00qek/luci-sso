#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"

static psa_status_t _psa_init_status = PSA_ERROR_BAD_STATE;

#define MAX_INPUT_SIZE 16384 // 16 KB

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

static uc_value_t *uc_mbedtls_verify_rs256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (_psa_init_status != PSA_SUCCESS) return ucv_boolean_new(false);

	if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
		return ucv_boolean_new(false);
	}

	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);
	const unsigned char *sig = (const unsigned char *)ucv_string_get(v_sig);
	size_t sig_len = ucv_string_length(v_sig);
	const char *key_pem = ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);

	if (msg_len > MAX_INPUT_SIZE || sig_len > MAX_INPUT_SIZE || key_len > MAX_INPUT_SIZE) {
		return ucv_boolean_new(false);
	}

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1) != 0) {
		mbedtls_pk_free(&pk);
		return ucv_boolean_new(false);
	}

	unsigned char hash[32];
	size_t out_len;
	if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &out_len) != PSA_SUCCESS) {
		mbedtls_pk_free(&pk);
		return ucv_boolean_new(false);
	}

	int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, out_len, sig, sig_len);
	mbedtls_pk_free(&pk);

	return ucv_boolean_new(ret == 0);
}

static uc_value_t *uc_mbedtls_verify_es256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (_psa_init_status != PSA_SUCCESS) return ucv_boolean_new(false);

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

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1) != 0) {
		mbedtls_pk_free(&pk);
		return ucv_boolean_new(false);
	}

	unsigned char hash[32];
	size_t out_len;
	if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &out_len) != PSA_SUCCESS) {
		mbedtls_pk_free(&pk);
		return ucv_boolean_new(false);
	}

	int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, out_len, der_sig, der_sig_len);
	mbedtls_pk_free(&pk);

	return ucv_boolean_new(ret == 0);
}

static uc_value_t *uc_mbedtls_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	if (ucv_type(arg) != UC_STRING) return NULL;
	if (_psa_init_status != PSA_SUCCESS) return NULL;
	
	const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
	size_t input_len = ucv_string_length(arg);
	unsigned char output[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
	size_t out_len;

	psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, input, input_len, 
	                                     output, sizeof(output), &out_len);
	
	if (status != PSA_SUCCESS) return NULL;

	return ucv_string_new_length((const char *)output, out_len);
}

static uc_value_t *uc_mbedtls_hmac_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_key = uc_fn_arg(0);
	uc_value_t *v_msg = uc_fn_arg(1);

	if (_psa_init_status != PSA_SUCCESS) return NULL;

	if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) {
		return NULL;
	}

	const unsigned char *key = (const unsigned char *)ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);
	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);

	unsigned char hashed_key[32];
	if (key_len > 64) { // RFC 2104: Hash keys longer than block size
		size_t hlen;
		if (psa_hash_compute(PSA_ALG_SHA_256, key, key_len, hashed_key, 32, &hlen) != PSA_SUCCESS) return NULL;
		key = hashed_key;
		key_len = hlen;
	}

	unsigned char mac[PSA_MAC_MAX_SIZE];
	size_t mac_len;

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

	psa_key_id_t key_id = 0;
	psa_status_t status = psa_import_key(&attributes, key, key_len, &key_id);
	if (status != PSA_SUCCESS) return NULL;

	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len,
	                         mac, sizeof(mac), &mac_len);
	
	psa_destroy_key(key_id);

	if (status != PSA_SUCCESS) return NULL;

	return ucv_string_new_length((const char *)mac, mac_len);
}

static uc_value_t *uc_mbedtls_random(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	int len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;
	if (len <= 0 || len > 4096) return NULL;
	if (_psa_init_status != PSA_SUCCESS) return NULL;

	unsigned char *buf = malloc(len);
	if (!buf) return NULL;

	psa_status_t status = psa_generate_random(buf, len);
	if (status != PSA_SUCCESS) {
		free(buf);
		return NULL;
	}

	uc_value_t *res = ucv_string_new_length((const char *)buf, len);
	free(buf);
	return res;
}

static uc_value_t *uc_mbedtls_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_n = uc_fn_arg(0);
	uc_value_t *v_e = uc_fn_arg(1);

	if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

	const unsigned char *n = (const unsigned char *)ucv_string_get(v_n);
	size_t n_len = ucv_string_length(v_n);
	const unsigned char *e = (const unsigned char *)ucv_string_get(v_e);
	size_t e_len = ucv_string_length(v_e);

	// Security: Reject exponents that are: Empty, Even, or Less than 3
	if (e_len == 0 || (e[e_len - 1] & 1) == 0) return NULL;
	if (e_len == 1 && e[0] < 3) return NULL;

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}

	if (mbedtls_rsa_import_raw(mbedtls_pk_rsa(pk), n, n_len, NULL, 0, NULL, 0, NULL, 0, e, e_len) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}

	unsigned char buf[4096]; 
	memset(buf, 0, sizeof(buf));
	if (mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf)) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}
	mbedtls_pk_free(&pk);

	return ucv_string_new((const char *)buf);
}

static uc_value_t *uc_mbedtls_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_x = uc_fn_arg(0);
	uc_value_t *v_y = uc_fn_arg(1);

	if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

	const unsigned char *x = (const unsigned char *)ucv_string_get(v_x);
	size_t x_len = ucv_string_length(v_x);
	const unsigned char *y = (const unsigned char *)ucv_string_get(v_y);
	size_t y_len = ucv_string_length(v_y);

	if (x_len != 32 || y_len != 32) return NULL;

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}

	mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
	if (mbedtls_ecp_group_load(&(ec->MBEDTLS_PRIVATE(grp)), MBEDTLS_ECP_DP_SECP256R1) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}

	unsigned char point[65];
	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);

	if (mbedtls_ecp_point_read_binary(&(ec->MBEDTLS_PRIVATE(grp)), &(ec->MBEDTLS_PRIVATE(Q)), point, 65) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}

	unsigned char buf[2048];
	memset(buf, 0, sizeof(buf));
	if (mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf)) != 0) {
		mbedtls_pk_free(&pk);
		return NULL;
	}
	mbedtls_pk_free(&pk);

	return ucv_string_new((const char *)buf);
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
	_psa_init_status = psa_crypto_init();
	uc_function_list_register(scope, mbedtls_fns);
}
