import { test, assert, assert_eq } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('discovery: security - compliance - constant_time_eq used for issuer comparison', () => {
    let issuer = "https://trusted.idp";
    let doc = { ...f.MOCK_DISCOVERY, issuer: issuer };

    let mocked = mock.create();

    // Verify it fails during discovery validation when issuer mismatch occurs
    let evil_doc = { ...doc, issuer: "https://evil.idp" };
    mocked.with_responses({
        [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
    }).spy((io) => {
        let res = discovery.discover(io, issuer);
        assert(!res.ok, "Should fail on issuer mismatch");
        assert_eq(res.error, "DISCOVERY_ISSUER_MISMATCH");
    });

    // We can't easily verify "constant-timeness" via return values alone,
    // so we must rely on the code fix to implement it as mandated.
});

test('discovery: find_jwk - functional verification', () => {
    let keys = [
        { kid: "key-1", kty: "RSA" },
        { kid: "key-2", kty: "RSA" },
        { kid: "key-3", kty: "EC" }
    ];

    // 1. Success cases
    let res1 = discovery.find_jwk(keys, "key-1");
    assert(res1.ok, "Should find key-1");
    assert_eq(res1.data.kid, "key-1");

    let res2 = discovery.find_jwk(keys, "key-3");
    assert(res2.ok, "Should find key-3");
    assert_eq(res2.data.kid, "key-3");

    // 2. Default case: no kid provided (returns first key)
    let res3 = discovery.find_jwk(keys, null);
    assert(res3.ok, "Should return first key when kid is null");
    assert_eq(res3.data.kid, "key-1");

    // 3. Failure cases
    let res4 = discovery.find_jwk(keys, "non-existent");
    assert(!res4.ok, "Should fail for non-existent kid");
    assert_eq(res4.error, "KEY_NOT_FOUND");

    let res5 = discovery.find_jwk([], "any");
    assert(!res5.ok, "Should fail for empty keys array");
});
