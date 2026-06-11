import { it, assert, truthy, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('discovery: security - compliance - constant_time_eq used for issuer comparison', () => {
	let issuer = "https://trusted.idp";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

	with_context({
		fs:          { data: {} },
		http_client: { data: { [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer);
		assert.match(falsy(), res.ok, "Should fail on issuer mismatch");
		assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
	});
});

it('discovery: find_jwk - functional verification', () => {
	let keys = [
		{ kid: "key-1", kty: "RSA" },
		{ kid: "key-2", kty: "RSA" },
		{ kid: "key-3", kty: "EC" }
	];

	let res1 = discovery.find_jwk(keys, "key-1");
	assert.match(truthy(), res1.ok, "Should find key-1");
	assert.match("key-1", res1.data.kid);

	let res2 = discovery.find_jwk(keys, "key-3");
	assert.match(truthy(), res2.ok, "Should find key-3");
	assert.match("key-3", res2.data.kid);

	let res3 = discovery.find_jwk(keys, null);
	assert.match(truthy(), res3.ok, "Should return first key when kid is null");
	assert.match("key-1", res3.data.kid);

	let res4 = discovery.find_jwk(keys, "non-existent");
	assert.match(falsy(), res4.ok, "Should fail for non-existent kid");
	assert.match("KEY_NOT_FOUND", res4.error);

	let res5 = discovery.find_jwk([], "any");
	assert.match(falsy(), res5.ok, "Should fail for empty keys array");
});
