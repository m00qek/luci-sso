import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';

test('native: memory safety - WolfSSL jwk_ec_p256_to_pem failed import (B1)', () => {
    // Inputs with wrong length (not 32 bytes) should definitely fail.
    // Coordinates that are not on the curve should also fail.
    
    let res = native.jwk_ec_p256_to_pem("too-short", "too-short");
    assert(res === null, "Should return null for too-short EC coordinates");

    let x_bad = "";
    for (let i = 0; i < 32; i++) x_bad += "A";
    let y_bad = "";
    for (let i = 0; i < 32; i++) y_bad += "B";
    
    res = native.jwk_ec_p256_to_pem(x_bad, y_bad);
    assert(res === null, "Should return null for invalid EC coordinates (not on curve)");
});
