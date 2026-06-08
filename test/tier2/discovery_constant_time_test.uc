import { it, assert, truthy, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

it('discovery: security - compliance - constant_time_eq used for issuer comparison', () => {
    let issuer = "https://trusted.idp";
    let doc = { ...f.MOCK_DISCOVERY, issuer: issuer };

    let mocked = mock.create();

    // Verify it fails during discovery validation when issuer mismatch occurs
    let evil_doc = { ...doc, issuer: "https://evil.idp" };
    mocked.with_responses({
        [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
    }).spy((io) => {
        let res = discovery.discover(io, issuer);
        assert.match(falsy(), res.ok, "Should fail on issuer mismatch");
        assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
    });

    // We can't easily verify "constant-timeness" via return values alone,
    // so we must rely on the code fix to implement it as mandated.
});

it('discovery: find_jwk - functional verification', () => {
    let keys = [
        { kid: "key-1", kty: "RSA" },
        { kid: "key-2", kty: "RSA" },
        { kid: "key-3", kty: "EC" }
    ];

    // 1. Success cases
    let res1 = discovery.find_jwk(keys, "key-1");
    assert.match(truthy(), res1.ok, "Should find key-1");
    assert.match("key-1", res1.data.kid);

    let res2 = discovery.find_jwk(keys, "key-3");
    assert.match(truthy(), res2.ok, "Should find key-3");
    assert.match("key-3", res2.data.kid);

    // 2. Default case: no kid provided (returns first key)
    let res3 = discovery.find_jwk(keys, null);
    assert.match(truthy(), res3.ok, "Should return first key when kid is null");
    assert.match("key-1", res3.data.kid);

    // 3. Failure cases
    let res4 = discovery.find_jwk(keys, "non-existent");
    assert.match(falsy(), res4.ok, "Should fail for non-existent kid");
    assert.match("KEY_NOT_FOUND", res4.error);

    let res5 = discovery.find_jwk([], "any");
    assert.match(falsy(), res5.ok, "Should fail for empty keys array");
});
