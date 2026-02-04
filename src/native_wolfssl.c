#include <ucode/module.h>

/**
 * Placeholder for WolfSSL backend.
 * Currently only implements signatures to allow CI setup.
 */

static uc_value_t *uc_wolfssl_verify_rs256(uc_vm_t *vm, size_t nargs) {
    return ucv_boolean_new(false);
}

static uc_value_t *uc_wolfssl_verify_es256(uc_vm_t *vm, size_t nargs) {
    return ucv_boolean_new(false);
}

static uc_value_t *uc_wolfssl_sha256(uc_vm_t *vm, size_t nargs) {
    return NULL;
}

static uc_value_t *uc_wolfssl_random(uc_vm_t *vm, size_t nargs) {
    return NULL;
}

static uc_value_t *uc_wolfssl_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
    return NULL;
}

static uc_value_t *uc_wolfssl_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
    return NULL;
}

static uc_value_t *uc_wolfssl_hmac_sha256(uc_vm_t *vm, size_t nargs) {
    return NULL;
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
