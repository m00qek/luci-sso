#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ucode/module.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "luci-sso OpenSSL backend requires OpenSSL 3.0 or later"
#endif

#define MAX_INPUT_SIZE 16384

#define VALIDATE_INPUT_SIZES(msg_len, sig_len, key_len) \
	do { \
		if ((msg_len) > MAX_INPUT_SIZE || (sig_len) > MAX_INPUT_SIZE || (key_len) > MAX_INPUT_SIZE) { \
			return ucv_boolean_new(false); \
		} \
	} while(0)

#define VALIDATE_INPUT_SIZES_NULL(msg_len, sig_len, key_len) \
	do { \
		if ((msg_len) > MAX_INPUT_SIZE || (sig_len) > MAX_INPUT_SIZE || (key_len) > MAX_INPUT_SIZE) { \
			return NULL; \
		} \
	} while(0)

static uc_value_t *uc_openssl_verify_rs256(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING)
		return ucv_boolean_new(false);

	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);
	const unsigned char *sig = (const unsigned char *)ucv_string_get(v_sig);
	size_t sig_len = ucv_string_length(v_sig);
	const char *key_pem = ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);

	VALIDATE_INPUT_SIZES(msg_len, sig_len, key_len);

	bool result = false;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;

	bio = BIO_new_mem_buf(key_pem, (int)key_len);
	if (!bio) goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey) goto out;

	/* SECURITY: Only accept RSA keys */
	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) goto out;

	/* SECURITY: Enforce minimum RSA key size (2048 bits) per NIST SP 800-57 */
	if (EVP_PKEY_bits(pkey) < 2048) goto out;

	ctx = EVP_MD_CTX_new();
	if (!ctx) goto out;

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto out;
	if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) goto out;
	result = (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1);

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	ERR_clear_error();
	return ucv_boolean_new(result);
}

static uc_value_t *uc_openssl_verify_es256(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v_msg = uc_fn_arg(0);
	uc_value_t *v_sig = uc_fn_arg(1);
	uc_value_t *v_key = uc_fn_arg(2);

	if (ucv_type(v_msg) != UC_STRING || ucv_type(v_sig) != UC_STRING || ucv_type(v_key) != UC_STRING)
		return ucv_boolean_new(false);

	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);
	const unsigned char *raw_sig = (const unsigned char *)ucv_string_get(v_sig);
	size_t raw_sig_len = ucv_string_length(v_sig);
	const char *key_pem = ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);

	if (raw_sig_len != 64) return ucv_boolean_new(false);
	VALIDATE_INPUT_SIZES(msg_len, raw_sig_len, key_len);

	bool result = false;
	BIGNUM *r = NULL, *s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	unsigned char *der_sig = NULL;
	int der_sig_len = 0;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	char curve[64];
	size_t curve_len = 0;

	/* Convert raw R||S (64 bytes) to DER-encoded ECDSA signature */
	r = BN_bin2bn(raw_sig, 32, NULL);
	s = BN_bin2bn(raw_sig + 32, 32, NULL);
	if (!r || !s) goto out;

	ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) goto out;

	if (!ECDSA_SIG_set0(ecdsa_sig, r, s)) goto out;
	r = s = NULL; /* ownership transferred to ecdsa_sig */

	der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
	if (der_sig_len <= 0) goto out;

	bio = BIO_new_mem_buf(key_pem, (int)key_len);
	if (!bio) goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey) goto out;

	/* SECURITY: Only accept EC keys */
	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) goto out;

	/* SECURITY: Only accept P-256 (prime256v1 / secp256r1) */
	if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
	                                   curve, sizeof(curve), &curve_len) != 1) goto out;
	if (strcmp(curve, "prime256v1") != 0 &&
	    strcmp(curve, "P-256") != 0 &&
	    strcmp(curve, "secp256r1") != 0) goto out;

	ctx = EVP_MD_CTX_new();
	if (!ctx) goto out;

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto out;
	if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) goto out;
	result = (EVP_DigestVerifyFinal(ctx, der_sig, der_sig_len) == 1);

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	if (der_sig) OPENSSL_free(der_sig);
	ECDSA_SIG_free(ecdsa_sig);
	BN_free(r);
	BN_free(s);
	ERR_clear_error();
	return ucv_boolean_new(result);
}

static uc_value_t *uc_openssl_sha256(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arg = uc_fn_arg(0);
	if (ucv_type(arg) != UC_STRING) return NULL;

	const unsigned char *input = (const unsigned char *)ucv_string_get(arg);
	size_t input_len = ucv_string_length(arg);

	VALIDATE_INPUT_SIZES_NULL(input_len, 0, 0);

	unsigned char output[32];
	unsigned int out_len = sizeof(output);

	if (EVP_Digest(input, input_len, output, &out_len, EVP_sha256(), NULL) != 1)
		return NULL;

	return ucv_string_new_length((const char *)output, out_len);
}

static uc_value_t *uc_openssl_hmac_sha256(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v_key = uc_fn_arg(0);
	uc_value_t *v_msg = uc_fn_arg(1);

	if (ucv_type(v_key) != UC_STRING || ucv_type(v_msg) != UC_STRING) return NULL;

	const unsigned char *key = (const unsigned char *)ucv_string_get(v_key);
	size_t key_len = ucv_string_length(v_key);
	const unsigned char *msg = (const unsigned char *)ucv_string_get(v_msg);
	size_t msg_len = ucv_string_length(v_msg);

	VALIDATE_INPUT_SIZES_NULL(msg_len, 0, key_len);

	uc_value_t *res = NULL;
	EVP_MAC *mac_impl = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	unsigned char mac_buf[32];
	size_t mac_len = sizeof(mac_buf);

	OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string("digest", "SHA256", 0),
		OSSL_PARAM_END
	};

	mac_impl = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!mac_impl) goto out;

	mac_ctx = EVP_MAC_CTX_new(mac_impl);
	if (!mac_ctx) goto out;

	if (EVP_MAC_init(mac_ctx, key, key_len, params) != 1) goto out;
	if (EVP_MAC_update(mac_ctx, msg, msg_len) != 1) goto out;
	if (EVP_MAC_final(mac_ctx, mac_buf, &mac_len, sizeof(mac_buf)) != 1) goto out;

	res = ucv_string_new_length((const char *)mac_buf, mac_len);

out:
	OPENSSL_cleanse(mac_buf, sizeof(mac_buf));
	EVP_MAC_CTX_free(mac_ctx);
	EVP_MAC_free(mac_impl);
	ERR_clear_error();
	return res;
}

static uc_value_t *uc_openssl_random(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *arg = uc_fn_arg(0);
	int len = (ucv_type(arg) == UC_INTEGER) ? (int)ucv_int64_get(arg) : 32;
	if (len <= 0 || len > 4096) return NULL;

	unsigned char *buf = malloc(len);
	if (!buf) return NULL;

	if (RAND_bytes(buf, len) != 1) {
		free(buf);
		return NULL;
	}

	uc_value_t *res = ucv_string_new_length((const char *)buf, len);
	OPENSSL_cleanse(buf, len);
	free(buf);
	return res;
}

static uc_value_t *uc_openssl_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v_n = uc_fn_arg(0);
	uc_value_t *v_e = uc_fn_arg(1);

	if (ucv_type(v_n) != UC_STRING || ucv_type(v_e) != UC_STRING) return NULL;

	const unsigned char *n = (const unsigned char *)ucv_string_get(v_n);
	size_t n_len = ucv_string_length(v_n);
	const unsigned char *e = (const unsigned char *)ucv_string_get(v_e);
	size_t e_len = ucv_string_length(v_e);

	/* Security: Reject exponents that are: Empty, Even, or Not exactly 65537 (RFC 4871) */
	if (e_len == 0 || (e[e_len - 1] & 1) == 0) return NULL;
	if (e_len != 3 || e[0] != 0x01 || e[1] != 0x00 || e[2] != 0x01) return NULL;

	uc_value_t *res = NULL;
	BIGNUM *bn_n = NULL, *bn_e = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;

	bn_n = BN_bin2bn(n, n_len, NULL);
	bn_e = BN_bin2bn(e, e_len, NULL);
	if (!bn_n || !bn_e) goto out;

	bld = OSSL_PARAM_BLD_new();
	if (!bld) goto out;

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e)) goto out;

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) goto out;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (!ctx) goto out;
	if (EVP_PKEY_fromdata_init(ctx) != 1) goto out;
	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio) goto out;
	if (PEM_write_bio_PUBKEY(bio, pkey) != 1) goto out;

	char *pem_data;
	long pem_len = BIO_get_mem_data(bio, &pem_data);
	if (pem_len > 0)
		res = ucv_string_new_length(pem_data, pem_len);

out:
	BIO_free(bio);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	BN_free(bn_n);
	BN_free(bn_e);
	ERR_clear_error();
	return res;
}

static uc_value_t *uc_openssl_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *v_x = uc_fn_arg(0);
	uc_value_t *v_y = uc_fn_arg(1);

	if (ucv_type(v_x) != UC_STRING || ucv_type(v_y) != UC_STRING) return NULL;

	const unsigned char *x = (const unsigned char *)ucv_string_get(v_x);
	size_t x_len = ucv_string_length(v_x);
	const unsigned char *y = (const unsigned char *)ucv_string_get(v_y);
	size_t y_len = ucv_string_length(v_y);

	if (x_len != 32 || y_len != 32) return NULL;

	uc_value_t *res = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *check_ctx = NULL;
	BIO *bio = NULL;

	/* Uncompressed EC point: 0x04 | X | Y */
	unsigned char point[65];
	point[0] = 0x04;
	memcpy(point + 1, x, 32);
	memcpy(point + 33, y, 32);

	bld = OSSL_PARAM_BLD_new();
	if (!bld) goto out;

	if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) ||
	    !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point))) goto out;

	params = OSSL_PARAM_BLD_to_param(bld);
	if (!params) goto out;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!ctx) goto out;
	if (EVP_PKEY_fromdata_init(ctx) != 1) goto out;
	if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) goto out;

	/* Defense-in-depth: verify point is on the curve */
	check_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!check_ctx) goto out;
	if (EVP_PKEY_public_check(check_ctx) != 1) goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio) goto out;
	if (PEM_write_bio_PUBKEY(bio, pkey) != 1) goto out;

	char *pem_data;
	long pem_len = BIO_get_mem_data(bio, &pem_data);
	if (pem_len > 0)
		res = ucv_string_new_length(pem_data, pem_len);

out:
	BIO_free(bio);
	EVP_PKEY_CTX_free(check_ctx);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	ERR_clear_error();
	return res;
}

static const uc_function_list_t openssl_fns[] = {
	{ "verify_rs256",       uc_openssl_verify_rs256 },
	{ "verify_es256",       uc_openssl_verify_es256 },
	{ "sha256",             uc_openssl_sha256 },
	{ "hmac_sha256",        uc_openssl_hmac_sha256 },
	{ "random",             uc_openssl_random },
	{ "jwk_rsa_to_pem",     uc_openssl_jwk_rsa_to_pem },
	{ "jwk_ec_p256_to_pem", uc_openssl_jwk_ec_p256_to_pem },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, openssl_fns);
}
