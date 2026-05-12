#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/misc.h>
#include <wolfssl/wolfcrypt/signature.h>

#include "native.h"

static void secure_memzero(void *p, size_t len){
	if (p == NULL || len == 0) return;
	volatile unsigned char *vp = (volatile unsigned char *)p;
	while (len--) *vp++ = 0;
}

static WC_RNG _global_rng;
static int _rng_initialized = 0;

int native_crypto_init(void) {
	if (!_rng_initialized) {
		if (wc_InitRng(&_global_rng) == 0) {
			_rng_initialized = 1;
		}
	}
	return _rng_initialized ? 0 : -1;
}

void native_crypto_deinit(void) {
	if (_rng_initialized) {
		wc_FreeRng(&_global_rng);
		_rng_initialized = 0;
	}
}

/**
 * Portable helper to convert PEM public key to DER.
 * wc_PubKeyPemToDer is not consistently exported in all WolfSSL builds (e.g. Alpine).
 * wc_PemToDer is more reliable and available in both OpenWrt and Alpine.
 */
static int portable_pubkey_pem_to_der(const char *pem, size_t pem_len, unsigned char *out, size_t out_len) {
	DerBuffer *der = NULL;
	int ret = wc_PemToDer((const unsigned char *)pem, (long)pem_len, PUBLICKEY_TYPE, &der, NULL, NULL, NULL);
	if (ret != 0 || der == NULL) {
		if (der) wc_FreeDer(&der);
		return -1;
	}

	if (der->length > out_len) {
		wc_FreeDer(&der);
		return -1;
	}

	memcpy(out, der->buffer, der->length);
	int final_len = (int)der->length;
	wc_FreeDer(&der);
	return final_len;
}

bool native_verify_rs256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len) {
	if (native_crypto_init() != 0) return false;

	RsaKey key;
	wc_InitRsaKey(&key, NULL);

	unsigned char der[NATIVE_RSA_PEM_MAX];
	int der_len = portable_pubkey_pem_to_der(key_pem, key_len, der, sizeof(der));
	if (der_len < 0) {
		wc_FreeRsaKey(&key);
		return false;
	}

	word32 idx = 0;
	if (wc_RsaPublicKeyDecode(der, &idx, &key, der_len) != 0) {
		wc_FreeRsaKey(&key);
		return false;
	}

	if (wc_RsaEncryptSize(&key) < (NATIVE_RSA_MIN_BITS / 8)) {
		wc_FreeRsaKey(&key);
		return false;
	}

	int ret = wc_SignatureVerify(
		WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC,
		msg, msg_len, sig, sig_len, &key, sizeof(key));

	wc_FreeRsaKey(&key);
	return (ret == 0);
}

bool native_verify_es256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len) {
	if (native_crypto_init() != 0) return false;

	ecc_key key;
	wc_ecc_init(&key);

	unsigned char der[NATIVE_EC_PEM_MAX];
	int der_len = portable_pubkey_pem_to_der(key_pem, key_len, der, sizeof(der));
	if (der_len < 0) {
		wc_ecc_free(&key);
		return false;
	}

	word32 idx = 0;
	if (wc_EccPublicKeyDecode(der, &idx, &key, der_len) != 0) {
		wc_ecc_free(&key);
		return false;
	}

	unsigned char der_sig[ECC_MAX_SIG_SIZE];
	word32 der_sig_len = sizeof(der_sig);

	if (wc_ecc_rs_raw_to_sig(sig, NATIVE_EC_COORD_SIZE, sig + NATIVE_EC_COORD_SIZE, NATIVE_EC_COORD_SIZE, der_sig, &der_sig_len) != 0) {
		wc_ecc_free(&key);
		return false;
	}

	unsigned char hash[NATIVE_SHA256_SIZE];
	if (wc_Sha256Hash(msg, msg_len, hash) != 0) {
		wc_ecc_free(&key);
		return false;
	}

	int verify_res = 0;
	if (wc_ecc_verify_hash(der_sig, der_sig_len, hash, sizeof(hash), &verify_res, &key) != 0) {
		secure_memzero(hash, sizeof(hash));
		wc_ecc_free(&key);
		return false;
	}

	secure_memzero(hash, sizeof(hash));
	wc_ecc_free(&key);
	return (verify_res == 1);
}

int native_sha256(const unsigned char *input, size_t input_len,
                  unsigned char *output) {
	if (wc_Sha256Hash(input, input_len, output) != 0) return -1;
	return 0;
}

int native_hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *msg, size_t msg_len,
                       unsigned char *output) {
	Hmac hmac;
	if (wc_HmacSetKey(&hmac, WC_SHA256, key, key_len) != 0) return -1;
	if (wc_HmacUpdate(&hmac, msg, msg_len) != 0) {
		secure_memzero(&hmac, sizeof(hmac));
		return -1;
	}
	if (wc_HmacFinal(&hmac, output) != 0) {
		secure_memzero(&hmac, sizeof(hmac));
		return -1;
	}
	secure_memzero(&hmac, sizeof(hmac));
	return 0;
}

int native_random(unsigned char *buf, size_t len) {
	if (native_crypto_init() != 0) return -1;
	if (wc_RNG_GenerateBlock(&_global_rng, buf, len) != 0) return -1;
	return 0;
}

void native_memzero(void *p, size_t len) {
	secure_memzero(p, len);
}

int native_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                          const unsigned char *e, size_t e_len,
                          char *out, size_t out_len) {
	RsaKey key;
	wc_InitRsaKey(&key, NULL);
	
	if (wc_RsaPublicKeyDecodeRaw(n, n_len, e, e_len, &key) != 0) {
		wc_FreeRsaKey(&key);
		return -1;
	}

	unsigned char der[NATIVE_RSA_PEM_MAX];
	int der_len = wc_RsaKeyToPublicDer(&key, der, sizeof(der));
	wc_FreeRsaKey(&key);
	if (der_len < 0) return -1;

	int pem_len = wc_DerToPem(der, der_len, (unsigned char *)out, out_len, PUBLICKEY_TYPE);
	return (pem_len < 0) ? -1 : 0;
}

int native_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                              const unsigned char *y, size_t y_len,
                              char *out, size_t out_len) {
	if (x_len != NATIVE_EC_COORD_SIZE || y_len != NATIVE_EC_COORD_SIZE) return -1;

	ecc_key key;
	wc_ecc_init(&key);

	unsigned char point[NATIVE_EC_POINT_SIZE];
	point[0] = 0x04;
	memcpy(point + 1, x, NATIVE_EC_COORD_SIZE);
	memcpy(point + 1 + NATIVE_EC_COORD_SIZE, y, NATIVE_EC_COORD_SIZE);

	if (wc_ecc_import_x963(point, sizeof(point), &key) != 0) {
		wc_ecc_free(&key);
		return -1;
	}

	unsigned char der[NATIVE_EC_PEM_MAX];
	int der_len = wc_EccPublicKeyToDer(&key, der, sizeof(der), 1);
	wc_ecc_free(&key);
	if (der_len < 0) return -1;

	int pem_len = wc_DerToPem(der, der_len, (unsigned char *)out, out_len, PUBLICKEY_TYPE);
	return (pem_len < 0) ? -1 : 0;
}
