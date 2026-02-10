#include <ucode/module.h>

/**
 * Placeholder for WolfSSL backend.
 * Currently NOT implemented. Calling any function will die.
 */

static void uc_wolfssl_die(uc_vm_t *vm, const char *msg) {
    uc_vm_raise_exception(vm, "NOT_IMPLEMENTED", "WolfSSL backend: %s", msg);
}

static uc_value_t *uc_wolfssl_verify_rs256(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "verify_rs256");
    return NULL;
}

static uc_value_t *uc_wolfssl_verify_es256(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "verify_es256");
    return NULL;
}

static uc_value_t *uc_wolfssl_sha256(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "sha256");
    return NULL;
}

static uc_value_t *uc_wolfssl_random(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "random");
    return NULL;
}

static uc_value_t *uc_wolfssl_jwk_rsa_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "jwk_rsa_to_pem");
    return NULL;
}

static uc_value_t *uc_wolfssl_jwk_ec_p256_to_pem(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "jwk_ec_p256_to_pem");
    return NULL;
}

static uc_value_t *uc_wolfssl_hmac_sha256(uc_vm_t *vm, size_t nargs) {
    uc_wolfssl_die(vm, "hmac_sha256");
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