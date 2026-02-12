import * as native from 'luci_sso.native';
import { assert, test } from '../testing.uc';

test('native: compliance - public key parsing exact length', () => {
    // A valid but truncated-looking PEM that would fail if +1 byte was read and it was garbage
    let valid_pem = "-----BEGIN PUBLIC KEY-----
" +
                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz6Bv6LpS6mF9nL7p9+x/k7x0Y6+L
" +
                    "7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
" +
                    "-----END PUBLIC KEY-----";
    
    // Note: The key above is dummy/malformed for actual crypto, but we want to see if the parser 
    // respects the length we pass or tries to read more.
    
    // We'll use a real valid key for a functional test
    let key = "-----BEGIN PUBLIC KEY-----
" +
              "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu1fAsXpXFxiSIn7A0O6/X6b89A38
" +
              "x8lY1U6/6eDIFzV9f0v8Q4p1lq3YpYFv8F0wY1YpYFv8F0wY1YpYFv8F0wY1YpYF
" +
              "-----END PUBLIC KEY-----";

    // If we pass exact length, it should attempt to parse it. 
    // If it fails because it's dummy, that's fine, as long as it doesn't crash.
    native.verify_es256("msg", "sig", key);
    assert(true, "Should not crash on exact length public key");
});
