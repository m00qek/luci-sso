#include <string.h>

#include "native_api.h"

/* Guards moved unchanged from the former native_common.c, plus output
 * termination for the PEM converters. See native_api.h for the contract. */

static bool within_ceiling(size_t a, size_t b, size_t c) {
	return a <= NATIVE_MAX_INPUT_SIZE && b <= NATIVE_MAX_INPUT_SIZE && c <= NATIVE_MAX_INPUT_SIZE;
}

bool native_api_verify_rs256(const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len,
                             const char *key_pem, size_t key_len) {
	if (!within_ceiling(msg_len, sig_len, key_len)) return false;

	return native_verify_rs256(msg, msg_len, sig, sig_len, key_pem, key_len);
}

bool native_api_verify_es256(const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len,
                             const char *key_pem, size_t key_len) {
	if (!within_ceiling(msg_len, sig_len, key_len)) return false;

	/* Protocol validation: ES256 signatures (ECDSA P-256) MUST be 64 bytes (R|S) */
	if (sig_len != NATIVE_ES256_SIG_SIZE) return false;

	return native_verify_es256(msg, msg_len, sig, sig_len, key_pem, key_len);
}

int native_api_sha256(const unsigned char *input, size_t input_len,
                      unsigned char *out) {
	if (!within_ceiling(input_len, 0, 0)) return -1;

	return native_sha256(input, input_len, out);
}

int native_api_hmac_sha256(const unsigned char *key, size_t key_len,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *out) {
	/* Security: an empty key means the caller lost its secret somewhere upstream.
	 * HMAC is defined for a zero-length key, so the backends disagree here:
	 * mbedtls' PSA refuses it, while wolfSSL's wc_HmacSetKey and OpenSSL's
	 * EVP_MAC accept it and return a MAC computed with no secret at all. Reject
	 * it here so every backend fails loudly rather than two of three silently
	 * authenticating with nothing. */
	if (key_len == 0) return -1;

	if (!within_ceiling(msg_len, 0, key_len)) return -1;

	if (native_hmac_sha256(key, key_len, msg, msg_len, out) != 0) {
		native_memzero(out, NATIVE_SHA256_SIZE);
		return -1;
	}
	return 0;
}

int native_api_random(unsigned char *buf, size_t buf_size, int64_t len) {
	if (len <= 0 || len > NATIVE_RANDOM_MAX || (uint64_t)len > buf_size) return -1;

	return native_random(buf, (size_t)len);
}

/* A backend PEM writer succeeded; make sure the result is a C string that
 * fits the buffer. wolfSSL's wc_DerToPem, for one, does not terminate. */
static int terminated_within(const char *out, size_t out_len) {
	return (out_len > 0 && memchr(out, '\0', out_len) != NULL) ? 0 : -1;
}

int native_api_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                              const unsigned char *e, size_t e_len,
                              char *out, size_t out_len) {
	/* Security: the modulus is attacker-supplied (it arrives in a JWKS document),
	 * so it needs the same 16 KB ceiling as every other input. mbedtls happens to
	 * reject an oversized modulus during key import; wolfSSL and OpenSSL do not. */
	if (!within_ceiling(n_len, 0, e_len)) return -1;

	/* Security: Reject exponents that are: Empty, Even, or Not exactly 65537 (RFC 4871)
	 * We only support the standard F4 exponent (0x010001) for safety and simplicity. */
	if (e_len != 3 || e[0] != 0x01 || e[1] != 0x00 || e[2] != 0x01) return -1;

	if (out_len == 0) return -1;
	memset(out, 0, out_len);
	if (native_jwk_rsa_to_pem(n, n_len, e, e_len, out, out_len) != 0) return -1;

	return terminated_within(out, out_len);
}

int native_api_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                                  const unsigned char *y, size_t y_len,
                                  char *out, size_t out_len) {
	/* Enforce P-256 coordinate lengths (32 bytes each) */
	if (x_len != NATIVE_EC_COORD_SIZE || y_len != NATIVE_EC_COORD_SIZE) return -1;

	if (out_len == 0) return -1;
	memset(out, 0, out_len);
	if (native_jwk_ec_p256_to_pem(x, x_len, y, y_len, out, out_len) != 0) return -1;

	return terminated_within(out, out_len);
}
