#include <string.h>
#include <ucode/module.h>

#include "native.h"
#include "native_api.h"

/*
 * ucode binding for the native crypto module.
 *
 * This layer only converts between ucode values and C buffers: it checks
 * argument types, unwraps strings, calls the guarded native_api_* entry
 * points, wraps the results and wipes secret-bearing buffers. It makes no
 * security decision about input sizes or content; those live in
 * native_api.c, where the fuzzer exercises them too.
 */

static uc_value_t *uc_native_verify_rs256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
		return ucv_boolean_new(false);
	}

	return ucv_boolean_new(native_api_verify_rs256(
		(const unsigned char *)ucv_string_get(v_msg), ucv_string_length(v_msg),
		(const unsigned char *)ucv_string_get(v_sig), ucv_string_length(v_sig),
		ucv_string_get(v_key), ucv_string_length(v_key)));
}

static uc_value_t *uc_native_verify_es256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING) {
		return ucv_boolean_new(false);
	}

	return ucv_boolean_new(native_api_verify_es256(
		(const unsigned char *)ucv_string_get(v_msg), ucv_string_length(v_msg),
		(const unsigned char *)ucv_string_get(v_sig), ucv_string_length(v_sig),
		ucv_string_get(v_key), ucv_string_length(v_key)));
}

static uc_value_t *uc_native_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	if (ucv_type(arg) != UC_STRING) return NULL;

	unsigned char output[NATIVE_SHA256_SIZE];
	if (native_api_sha256((const unsigned char *)ucv_string_get(arg), ucv_string_length(arg), output) != 0)
		return NULL;

	return ucv_string_new_length((const char *)output, NATIVE_SHA256_SIZE);
}

static uc_value_t *uc_native_hmac_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_key = uc_fn_arg(0);
	uc_value_t *v_msg = uc_fn_arg(1);

	if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) return NULL;

	unsigned char mac[NATIVE_SHA256_SIZE];
	if (native_api_hmac_sha256(
			(const unsigned char *)ucv_string_get(v_key), ucv_string_length(v_key),
			(const unsigned char *)ucv_string_get(v_msg), ucv_string_length(v_msg),
			mac) != 0) {
		return NULL;
	}

	uc_value_t *res = ucv_string_new_length((const char *)mac, NATIVE_SHA256_SIZE);
	native_memzero(mac, sizeof(mac));
	return res;
}

static uc_value_t *uc_native_random(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	/* Binding semantics: a missing or non-integer argument means 32 bytes. */
	int64_t len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;

	unsigned char buf[NATIVE_RANDOM_MAX];
	if (native_api_random(buf, sizeof(buf), len) != 0) return NULL;

	uc_value_t *res = ucv_string_new_length((const char *)buf, (size_t)len);
	native_memzero(buf, (size_t)len);
	return res;
}

static uc_value_t *uc_native_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_n = uc_fn_arg(0);
	uc_value_t *v_e = uc_fn_arg(1);

	if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

	char pem[NATIVE_RSA_PEM_MAX];
	if (native_api_jwk_rsa_to_pem(
			(const unsigned char *)ucv_string_get(v_n), ucv_string_length(v_n),
			(const unsigned char *)ucv_string_get(v_e), ucv_string_length(v_e),
			pem, sizeof(pem)) != 0) {
		return NULL;
	}

	return ucv_string_new_length(pem, strnlen(pem, sizeof(pem)));
}

static uc_value_t *uc_native_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_x = uc_fn_arg(0);
	uc_value_t *v_y = uc_fn_arg(1);

	if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

	char pem[NATIVE_EC_PEM_MAX];
	if (native_api_jwk_ec_p256_to_pem(
			(const unsigned char *)ucv_string_get(v_x), ucv_string_length(v_x),
			(const unsigned char *)ucv_string_get(v_y), ucv_string_length(v_y),
			pem, sizeof(pem)) != 0) {
		return NULL;
	}

	return ucv_string_new_length(pem, strnlen(pem, sizeof(pem)));
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
