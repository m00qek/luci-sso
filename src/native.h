#ifndef NATIVE_H
#define NATIVE_H

#include <stddef.h>
#include <stdbool.h>

/* --- Security & Protocol Constants --- */
#define NATIVE_MAX_INPUT_SIZE   16384   // 16 KB
#define NATIVE_SHA256_SIZE      32
#define NATIVE_RSA_MIN_BITS     2048
#define NATIVE_ES256_SIG_SIZE   64
#define NATIVE_EC_COORD_SIZE    32
#define NATIVE_EC_POINT_SIZE    (2 * NATIVE_EC_COORD_SIZE + 1)
#define NATIVE_RSA_PEM_MAX      4096
#define NATIVE_EC_PEM_MAX       2048

/**
 * Initialize the crypto backend.
 * Returns 0 on success, non-zero otherwise.
 */
int native_crypto_init(void);

/**
 * Verify RS256 signature.
 * Returns true on success, false otherwise.
 */
bool native_verify_rs256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len);

/**
 * Verify ES256 signature.
 * Returns true on success, false otherwise.
 */
bool native_verify_es256(const unsigned char *msg, size_t msg_len,
                         const unsigned char *sig, size_t sig_len,
                         const char *key_pem, size_t key_len);

/**
 * Compute SHA256 hash.
 * 'output' must be a buffer of at least 32 bytes.
 * Returns 0 on success, non-zero otherwise.
 */
int native_sha256(const unsigned char *input, size_t input_len,
                  unsigned char *output);

/**
 * Compute HMAC-SHA256.
 * 'output' must be a buffer of at least 32 bytes.
 * Returns 0 on success, non-zero otherwise.
 */
int native_hmac_sha256(const unsigned char *key, size_t key_len,
                       const unsigned char *msg, size_t msg_len,
                       unsigned char *output);

/**
 * Generate random bytes.
 * Returns 0 on success, non-zero otherwise.
 */
int native_random(unsigned char *buf, size_t len);

/**
 * Securely zeroize memory.
 */
void native_memzero(void *p, size_t len);

/**
 * Convert RSA JWK components (N, E) to PEM.
 * Writes result to 'out' (max size 'out_len').
 * Returns 0 on success, non-zero otherwise.
 */
int native_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                          const unsigned char *e, size_t e_len,
                          char *out, size_t out_len);

/**
 * Convert EC JWK components (X, Y) to PEM.
 * Writes result to 'out' (max size 'out_len').
 * Returns 0 on success, non-zero otherwise.
 */
int native_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                              const unsigned char *y, size_t y_len,
                              char *out, size_t out_len);

#endif /* NATIVE_H */
