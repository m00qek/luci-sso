#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"

#include "native.h"

static psa_status_t _psa_init_status = PSA_ERROR_BAD_STATE;

int native_crypto_init(void) {
    _psa_init_status = psa_crypto_init();
    return (_psa_init_status == PSA_SUCCESS) ? 0 : -1;
}

void native_crypto_deinit(void) {
    mbedtls_psa_crypto_free();
    _psa_init_status = PSA_ERROR_BAD_STATE;
}

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

bool native_verify_rs256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len) {
	if (_psa_init_status != PSA_SUCCESS) return false;

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	// mbedtls_pk_parse_public_key expects a null-terminated string including the terminator in the length for PEM.
	// We assume key_pem is null-terminated and key_len is the length WITHOUT the terminator (ucode standard).
	if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1) != 0) {
		mbedtls_pk_free(&pk);
		return false;
	}

	/* SECURITY: Enforce minimum RSA key size (2048 bits) per NIST SP 800-57 */
	if (mbedtls_pk_get_bitlen(&pk) < NATIVE_RSA_MIN_BITS) {
		mbedtls_pk_free(&pk);
		return false;
	}

	unsigned char hash[NATIVE_SHA256_SIZE];
	size_t out_len;
	if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &out_len) != PSA_SUCCESS) {
		mbedtls_pk_free(&pk);
		return false;
	}

	int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, out_len, sig, sig_len);
	mbedtls_platform_zeroize(hash, sizeof(hash));
	mbedtls_pk_free(&pk);

	return (ret == 0);
}

bool native_verify_es256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len) {
	if (_psa_init_status != PSA_SUCCESS) return false;

	unsigned char der_buf[128]; 
	unsigned char *der_sig = NULL;
	size_t der_sig_len = 0;

	if (ecdsa_raw_to_der_robust(sig, sig_len, der_buf, sizeof(der_buf), &der_sig, &der_sig_len) != 0) {
		return false;
	}

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);

	// mbedtls_pk_parse_public_key expects a null-terminated string including the terminator in the length for PEM.
	// We assume key_pem is null-terminated and key_len is the length WITHOUT the terminator (ucode standard).
	if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)key_pem, key_len + 1) != 0) {
		mbedtls_pk_free(&pk);
		return false;
	}

	unsigned char hash[NATIVE_SHA256_SIZE];
	size_t out_len;
	if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &out_len) != PSA_SUCCESS) {
		mbedtls_pk_free(&pk);
		return false;
	}

	int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, out_len, der_sig, der_sig_len);
	mbedtls_platform_zeroize(hash, sizeof(hash));
	mbedtls_pk_free(&pk);

	return (ret == 0);
}

int native_sha256(const unsigned char *input, size_t input_len,
                  unsigned char *output) {
	if (_psa_init_status != PSA_SUCCESS) return -1;
	
	size_t out_len;
	psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, input, input_len, 
	                                     output, NATIVE_SHA256_SIZE, &out_len);
	
	return (status == PSA_SUCCESS) ? 0 : -1;
}

int native_hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *msg, size_t msg_len,
                       unsigned char *output) {
	if (_psa_init_status != PSA_SUCCESS) return -1;

	unsigned char hashed_key[NATIVE_SHA256_SIZE];
	if (key_len > 64) {
		size_t hlen;
		if (psa_hash_compute(PSA_ALG_SHA_256, key, key_len, hashed_key, sizeof(hashed_key), &hlen) != PSA_SUCCESS) return -1;
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
	
	if (key == hashed_key) {
		mbedtls_platform_zeroize(hashed_key, sizeof(hashed_key));
	}

	if (status != PSA_SUCCESS) return -1;

	status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), msg, msg_len,
	                         mac, sizeof(mac), &mac_len);
	
	psa_destroy_key(key_id);

	if (status != PSA_SUCCESS) return -1;

	memcpy(output, mac, NATIVE_SHA256_SIZE);
	mbedtls_platform_zeroize(mac, sizeof(mac));
	return 0;
}

int native_random(unsigned char *buf, size_t len) {
	if (_psa_init_status != PSA_SUCCESS) return -1;

	psa_status_t status = psa_generate_random(buf, len);
	return (status == PSA_SUCCESS) ? 0 : -1;
}

void native_memzero(void *p, size_t len) {
	mbedtls_platform_zeroize(p, len);
}

int native_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                          const unsigned char *e, size_t e_len,
                          char *out, size_t out_len) {
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	if (mbedtls_rsa_import_raw(mbedtls_pk_rsa(pk), n, n_len, NULL, 0, NULL, 0, NULL, 0, e, e_len) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	if (mbedtls_pk_write_pubkey_pem(&pk, (unsigned char *)out, out_len) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}
	mbedtls_pk_free(&pk);

	return 0;
}

int native_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                              const unsigned char *y, size_t y_len,
                              char *out, size_t out_len) {
	if (x_len != NATIVE_EC_COORD_SIZE || y_len != NATIVE_EC_COORD_SIZE) return -1;

	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
	if (mbedtls_ecp_group_load(&(ec->MBEDTLS_PRIVATE(grp)), MBEDTLS_ECP_DP_SECP256R1) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	unsigned char point[NATIVE_EC_POINT_SIZE];
	point[0] = 0x04;
	memcpy(point + 1, x, NATIVE_EC_COORD_SIZE);
	memcpy(point + 1 + NATIVE_EC_COORD_SIZE, y, NATIVE_EC_COORD_SIZE);

	if (mbedtls_ecp_point_read_binary(&(ec->MBEDTLS_PRIVATE(grp)), &(ec->MBEDTLS_PRIVATE(Q)), point, sizeof(point)) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	if (mbedtls_ecp_check_pubkey(&(ec->MBEDTLS_PRIVATE(grp)), &(ec->MBEDTLS_PRIVATE(Q))) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}

	if (mbedtls_pk_write_pubkey_pem(&pk, (unsigned char *)out, out_len) != 0) {
		mbedtls_pk_free(&pk);
		return -1;
	}
	mbedtls_pk_free(&pk);

	return 0;
}
