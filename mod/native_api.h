#ifndef NATIVE_API_H
#define NATIVE_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "native.h"

/*
 * Guarded entry points of the native crypto module.
 *
 * Every decision about untrusted input lives here: size ceilings, exact
 * lengths, the RSA exponent allow-list, the empty-HMAC-key rejection, the
 * random length bounds, and output termination. Each function checks its
 * inputs and then calls the backend's native_* function from native.h.
 *
 * This file has no ucode dependency on purpose. The ucode binding
 * (native_ucode.c) and the libFuzzer harness (test/fuzz_test.c) both call
 * these functions, so the fuzzer exercises the exact path production uses.
 * A new backend implements native.h and inherits every guard below.
 */

/* Largest byte count random() may be asked for. */
#define NATIVE_RANDOM_MAX 4096

/*
 * Verify an RS256 / ES256 signature. key_pem must be NUL-terminated at
 * key_pem[key_len] (mbedtls parses PEM with the terminator included).
 * ES256 signatures must be raw R|S, exactly NATIVE_ES256_SIG_SIZE bytes.
 * Every input is capped at NATIVE_MAX_INPUT_SIZE.
 */
bool native_api_verify_rs256(const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len,
                             const char *key_pem, size_t key_len);

bool native_api_verify_es256(const unsigned char *msg, size_t msg_len,
                             const unsigned char *sig, size_t sig_len,
                             const char *key_pem, size_t key_len);

/* SHA-256 of at most NATIVE_MAX_INPUT_SIZE bytes into out[NATIVE_SHA256_SIZE].
 * Returns 0 on success. */
int native_api_sha256(const unsigned char *input, size_t input_len,
                      unsigned char *out);

/* HMAC-SHA256 into out[NATIVE_SHA256_SIZE]. Rejects an empty key: HMAC
 * defines one, but here it means the caller lost its secret. out is zeroed
 * on failure. Returns 0 on success. */
int native_api_hmac_sha256(const unsigned char *key, size_t key_len,
                           const unsigned char *msg, size_t msg_len,
                           unsigned char *out);

/* Fill buf[0..len) with CSPRNG output. len must be in 1..NATIVE_RANDOM_MAX
 * and no larger than buf_size. Returns 0 on success. */
int native_api_random(unsigned char *buf, size_t buf_size, int64_t len);

/* Convert JWK key material to a PUBLIC KEY PEM in out. On success out holds
 * a NUL-terminated string, whatever the backend does. RSA accepts only the
 * F4 exponent (65537) and at most NATIVE_MAX_INPUT_SIZE bytes of modulus;
 * EC takes exactly NATIVE_EC_COORD_SIZE bytes per coordinate. Returns 0 on
 * success. */
int native_api_jwk_rsa_to_pem(const unsigned char *n, size_t n_len,
                              const unsigned char *e, size_t e_len,
                              char *out, size_t out_len);

int native_api_jwk_ec_p256_to_pem(const unsigned char *x, size_t x_len,
                                  const unsigned char *y, size_t y_len,
                                  char *out, size_t out_len);

#endif /* NATIVE_API_H */
