import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';

// 512-bit RSA Public Key (Weak but validly signed)
const WEAK_RSA_PUB = "-----BEGIN PUBLIC KEY-----\n" +
"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALKUJMgLRqyOe0qduWFM0bMxt8SvyZQs\n" +
"2AyuPgvH0FdCMWpvH5yK0AR13gtJWtFfyxDCfFrBZ79JT7z7fs+StPUCAwEAAQ==\n" +
"-----END PUBLIC KEY-----";

// Valid signature for "test message" using the private counterpart of WEAK_RSA_PUB
const WEAK_RSA_SIG_B64 = "NQIvIQu5i0YKhIwhsvCqrYeNqKxQTABrufd0ssfVn/JezIJL67hET6S0kCdAQKv4Fv/a4Hxwqtz6FxUTsq4F0A==";

test('native: security - RSA minimum key size enforcement (2048 bits)', () => {
    let msg = "test message";
    let sig = b64dec(WEAK_RSA_SIG_B64); 

    // This SHOULD return false because the key is only 512 bits.
    // Currently, it is expected to return true (VULNERABLE).
    let res = native.verify_rs256(msg, sig, WEAK_RSA_PUB);
    
    assert(!res, "Verification SHOULD fail for weak 512-bit RSA key even if signature is valid");
});
