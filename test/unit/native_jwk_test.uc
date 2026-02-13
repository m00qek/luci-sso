import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';
import * as f from 'unit.tier0_fixtures';

function hex_to_bin(h) {
    let s = "";
    for (let i = 0; i < length(h); i += 2) {
        s += chr(hex(substr(h, i, 2)));
    }
    return s;
}

test('native: JWK - EC P-256 to PEM conversion', () => {
    // Coordinates extracted from f.EC_256.pub
    let x_hex = "2ca49943de78ced53c36683e3d90df1668bff173597f85daa7d6804e4c659cce";
    let y_hex = "141ed122e7bcffa24d35e37c81830bf9b8006a9acbf60fcdf80a862405e357fb";
    
    let x_bin = hex_to_bin(x_hex);
    let y_bin = hex_to_bin(y_hex);
    
    let pem = native.jwk_ec_p256_to_pem(x_bin, y_bin);
    assert(pem, "Should successfully convert EC JWK to PEM");
    assert(index(pem, "BEGIN PUBLIC KEY") >= 0, "Should produce a PUBLIC KEY PEM");
    
    // Verify the produced PEM works for signature verification
    let sig = hex_to_bin(f.EC_256.sig_hex);
    let res = native.verify_es256(f.EC_256.msg, sig, pem);
    assert(res, "Produced PEM must work for ES256 verification");
});
