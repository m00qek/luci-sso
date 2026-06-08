#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

#include "native.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "luci-sso OpenSSL backend requires OpenSSL 3.0 or later"
#endif

int native_crypto_init(void)
{
	return 0;
}

void native_crypto_deinit(void)
{
	ERR_free_strings();
	EVP_cleanup();
}

void native_memzero(void *p, size_t len)
{
	if (p) OPENSSL_cleanse(p, len);
}

bool native_verify_rs256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len)
{
	if (msg_len > NATIVE_MAX_INPUT_SIZE || sig_len > NATIVE_MAX_INPUT_SIZE || key_len > NATIVE_MAX_INPUT_SIZE)
		return false;

	bool result = false;
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;

	bio = BIO_new_mem_buf(key_pem, (int)key_len);
	if (!bio) goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey) goto out;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) goto out;
	if (EVP_PKEY_bits(pkey) < NATIVE_RSA_MIN_BITS) goto out;

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
	return result;
}

bool native_verify_es256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *raw_sig, size_t raw_sig_len,
                         const char *key_pem, size_t key_len)
{
	if (msg_len > NATIVE_MAX_INPUT_SIZE || raw_sig_len != NATIVE_ES256_SIG_SIZE || key_len > NATIVE_MAX_INPUT_SIZE)
		return false;

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

	r = BN_bin2bn(raw_sig, 32, NULL);
	s = BN_bin2bn(raw_sig + 32, 32, NULL);
	if (!r || !s) goto out;

	ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) goto out;

	if (!ECDSA_SIG_set0(ecdsa_sig, r, s)) goto out;
	r = s = NULL;

	der_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
	if (der_sig_len <= 0) goto out;

	bio = BIO_new_mem_buf(key_pem, (int)key_len);
	if (!bio) goto out;

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pkey) goto out;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) goto out;
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
	return result;
}

int native_sha256(const unsigned char *input, size_t input_len, unsigned char *output)
{
	if (input_len > NATIVE_MAX_INPUT_SIZE) return -1;
	unsigned int out_len = 32;
	if (EVP_Digest(input, input_len, output, &out_len, EVP_sha256(), NULL) != 1) return -1;
	return 0;
}

int native_hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *msg, size_t msg_len,
                       unsigned char *output)
{
	if (msg_len > NATIVE_MAX_INPUT_SIZE || key_len > NATIVE_MAX_INPUT_SIZE) return -1;

	int res = -1;
	EVP_MAC *mac_impl = NULL;
	EVP_MAC_CTX *mac_ctx = NULL;
	size_t mac_len = 32;

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
	if (EVP_MAC_final(mac_ctx, output, &mac_len, 32) != 1) goto out;

	res = 0;

out:
	EVP_MAC_CTX_free(mac_ctx);
	EVP_MAC_free(mac_impl);
	ERR_clear_error();
	return res;
}

int native_random(unsigned char *buf, size_t len)
{
	if (len > 4096) return -1;
	if (RAND_bytes(buf, (int)len) != 1) return -1;
	return 0;
}

int native_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                          const unsigned char *e, size_t e_len,
                          char *out, size_t out_len)
{
	if (e_len == 0 || (e[e_len - 1] & 1) == 0) return -1;
	if (e_len != 3 || e[0] != 0x01 || e[1] != 0x00 || e[2] != 0x01) return -1;

	int res = -1;
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
	if (pem_len > 0 && (size_t)pem_len < out_len) {
		memcpy(out, pem_data, pem_len);
		out[pem_len] = '\0';
		res = 0;
	}

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

int native_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                              const unsigned char *y, size_t y_len,
                              char *out, size_t out_len)
{
	if (x_len != NATIVE_EC_COORD_SIZE || y_len != NATIVE_EC_COORD_SIZE) return -1;

	int res = -1;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *check_ctx = NULL;
	BIO *bio = NULL;

	unsigned char point[NATIVE_EC_POINT_SIZE];
	point[0] = 0x04;
	memcpy(point + 1, x, NATIVE_EC_COORD_SIZE);
	memcpy(point + 33, y, NATIVE_EC_COORD_SIZE);

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

	check_ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!check_ctx) goto out;
	if (EVP_PKEY_public_check(check_ctx) != 1) goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio) goto out;
	if (PEM_write_bio_PUBKEY(bio, pkey) != 1) goto out;

	char *pem_data;
	long pem_len = BIO_get_mem_data(bio, &pem_data);
	if (pem_len > 0 && (size_t)pem_len < out_len) {
		memcpy(out, pem_data, pem_len);
		out[pem_len] = '\0';
		res = 0;
	}

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
