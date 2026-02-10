#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static WC_RNG _global_rng;
static int _rng_initialized = 0;

static uc_value_t *uc_wolfssl_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	if (ucv_type(arg) != UC_STRING) return NULL;
	
	const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
	size_t input_len = ucv_string_length(arg);
	unsigned char output[WC_SHA256_DIGEST_SIZE];

	if (wc_Sha256Hash(input, input_len, output) != 0) return NULL;

	return ucv_string_new_length((const char *)output, WC_SHA256_DIGEST_SIZE);
}

static uc_value_t *uc_wolfssl_hmac_sha256(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_key = uc_fn_arg(0);
	uc_value_t *v_msg = uc_fn_arg(1);

	if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) return NULL;

	const unsigned char *key = (const unsigned char *)ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);
	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);

	Hmac hmac;
	unsigned char mac[WC_SHA256_DIGEST_SIZE];

	if (wc_HmacSetKey(&hmac, WC_SHA256, key, key_len) != 0) return NULL;
	if (wc_HmacUpdate(&hmac, msg, msg_len) != 0) return NULL;
	if (wc_HmacFinal(&hmac, mac) != 0) return NULL;

	return ucv_string_new_length((const char *)mac, WC_SHA256_DIGEST_SIZE);
}

static uc_value_t *uc_wolfssl_random(uc_vm_t *vm, size_t nargs) {
	uc_value_t *arg = uc_fn_arg(0);
	int len = (ucv_type(arg) == UC_INTEGER) ? ucv_int64_get(arg) : 32;
	if (len <= 0 || len > 4096) return NULL;

	if (!_rng_initialized) {
		if (wc_InitRng(&_global_rng) != 0) return NULL;
		_rng_initialized = 1;
	}

	unsigned char *buf = malloc(len);
	if (!buf) return NULL;

	if (wc_RNG_GenerateBlock(&_global_rng, buf, len) != 0) {
		free(buf);
		return NULL;
	}

	uc_value_t *res = ucv_string_new_length((const char *)buf, len);
	free(buf);
	return res;
}

static uc_value_t *uc_wolfssl_verify_rs256(uc_vm_t *vm, size_t nargs) {
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
	const unsigned char *key_pem = (const unsigned char *)ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);

	// Hash the message
	unsigned char hash[WC_SHA256_DIGEST_SIZE];
	if (wc_Sha256Hash(msg, msg_len, hash) != 0) return ucv_boolean_new(false);

	RsaKey key;
	wc_InitRsaKey(&key, NULL);
	
	word32 idx = 0;
	// WolfSSL can parse PEM directly if configured, or we use Der
	// Most OpenWrt WolfSSL builds support PEM
	if (wc_PubKeyPemToDer(key_pem, key_len, NULL, 0) < 0) {
		// If it's not PEM, it might already be DER
	}

	// For simplicity and robustness, we use the high-level PKCS1v1.5 verify
	// But first we need to load the key.
	// Since we only have Public Key PEM, we use wc_RsaPublicKeyDecode
	// But we need DER first.
	unsigned char der[4096];
	int der_len = wc_PubKeyPemToDer(key_pem, key_len, der, sizeof(der));
	if (der_len < 0) {
		wc_FreeRsaKey(&key);
		return ucv_boolean_new(false);
	}

	if (wc_RsaPublicKeyDecode(der, &idx, &key, der_len) != 0) {
		wc_FreeRsaKey(&key);
		return ucv_boolean_new(false);
	}

	int res = wc_RsaSSL_Verify(sig, sig_len, hash, WC_SHA256_DIGEST_SIZE, &key);
	wc_FreeRsaKey(&key);

	return ucv_boolean_new(res >= 0);
}

static uc_value_t *uc_wolfssl_verify_es256(uc_vm_t *vm, size_t nargs) {
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
	const unsigned char *key_pem = (const unsigned char *)ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);

	if (raw_sig_len != 64) return ucv_boolean_new(false);

	unsigned char hash[WC_SHA256_DIGEST_SIZE];
	if (wc_Sha256Hash(msg, msg_len, hash) != 0) return ucv_boolean_new(false);

	ecc_key key;
	wc_ecc_init(&key);

	unsigned char der[1024];
	int der_len = wc_PubKeyPemToDer(key_pem, key_len, der, sizeof(der));
	if (der_len < 0) {
		wc_ecc_free(&key);
		return ucv_boolean_new(false);
	}

	word32 idx = 0;
	if (wc_EccPublicKeyDecode(der, &idx, &key, der_len) != 0) {
		wc_ecc_free(&key);
		return ucv_boolean_new(false);
	}

	int verify_res = 0;
	// raw_sig is R|S (64 bytes). WolfSSL wc_ecc_verify_hash expects this.
	if (wc_ecc_verify_hash(raw_sig, raw_sig_len, hash, WC_SHA256_DIGEST_SIZE, &verify_res, &key) != 0) {
		wc_ecc_free(&key);
		return ucv_boolean_new(false);
	}

	wc_ecc_free(&key);
	return ucv_boolean_new(verify_res == 1);
}

static uc_value_t *uc_wolfssl_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_n = uc_fn_arg(0);
	uc_value_t *v_e = uc_fn_arg(1);

	if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

	const unsigned char *n = (const unsigned char *)ucv_string_get(v_n);
	size_t n_len = ucv_string_length(v_n);
	const unsigned char *e = (const unsigned char *)ucv_string_get(v_e);
	size_t e_len = ucv_string_length(v_e);

	// N2: Reject exponents that are: Empty, Even, or Less than 3
	if (e_len == 0 || (e[e_len - 1] & 1) == 0) return NULL;
	if (e_len == 1 && e[0] < 3) return NULL;

	RsaKey key;
	wc_InitRsaKey(&key, NULL);
	
	if (wc_RsaPublicKeyDecodeRaw(n, n_len, e, e_len, &key) != 0) {
		wc_FreeRsaKey(&key);
		return NULL;
	}

	unsigned char der[2048];
	int der_len = wc_RsaKeyToDer(&key, der, sizeof(der));
	wc_FreeRsaKey(&key);
	if (der_len < 0) return NULL;

	unsigned char pem[4096];
	int pem_len = wc_DerToPem(der, der_len, pem, sizeof(pem), PUBLICKEY_TYPE);
	if (pem_len < 0) return NULL;

	return ucv_string_new((const char *)pem);
}

static uc_value_t *uc_wolfssl_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
	uc_value_t *v_x = uc_fn_arg(0);
	uc_value_t *v_y = uc_fn_arg(1);

	if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

	const unsigned char *x = (const unsigned char *)ucv_string_get(v_x);
	size_t x_len = ucv_string_length(v_x);
	const unsigned char *y = (const unsigned char *)ucv_string_get(v_y);
	size_t y_len = ucv_string_length(v_y);

	if (x_len != 32 || y_len != 32) return NULL;

	ecc_key key;
	wc_ecc_init(&key);

	// Create uncompressed point: 0x04 | X | Y
	unsigned char point[65];
	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);

	if (wc_ecc_import_x963(point, 65, &key) != 0) {
		wc_ecc_free(&key);
		return NULL;
	}

	unsigned char der[1024];
	int der_len = wc_EccKeyToDer(&key, der, sizeof(der));
	wc_ecc_free(&key);
	if (der_len < 0) return NULL;

	unsigned char pem[2048];
	int pem_len = wc_DerToPem(der, der_len, pem, sizeof(pem), PUBLICKEY_TYPE);
	if (pem_len < 0) return NULL;

	return ucv_string_new((const char *)pem);
}

static const uc_function_list_t wolfssl_fns[] = {
	{ "verify_rs256", uc_wolfssl_verify_rs256 },
	{ "verify_es256", uc_wolfssl_verify_es256 },
	{ "sha256", uc_wolfssl_sha256 },
	{ "hmac_sha256", uc_wolfssl_hmac_sha256 },
	{ "random", uc_wolfssl_random },
	{ "jwk_rsa_to_pem", uc_wolfssl_jwk_rsa_to_pem },
	{ "jwk_ec_p256_to_pem", uc_wolfssl_jwk_ec_p256_to_pem },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) {
	uc_function_list_register(scope, wolfssl_fns);
}