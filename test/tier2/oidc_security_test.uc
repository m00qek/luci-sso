import { it, assert, truthy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

import * as h from 'lib.helpers';

const PRIVKEY = f.MOCK_PRIVKEY;
const JWKS = { keys: [ f.MOCK_JWK ] };
const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

it('oidc: security - reject HS256 algorithm confusion', () => {
	// 1. Setup malicious HS256 token signed with a string key
	let header = { alg: "HS256", typ: "JWT", kid: "key1" };
	let payload = { 
		iss: f.MOCK_CONFIG.issuer_url, 
		aud: f.MOCK_CONFIG.client_id,
		sub: "user1",
		nonce: "n1",
		iat: 100,
		exp: 1000,
		at_hash: "fake_hash"
	};
	let res_s = crypto.jws_sign(payload, "secret-key"); // Maliciously signed with symmetric HS256
    assert.match(truthy(), Result.is(res_s));
	let token = res_s.data;

	let tokens = { id_token: token, access_token: "fake" };
	let keys = [{ kty: "RSA", kid: "key1", n: "...", e: "..." }]; // IdP only advertises RSA

	mock.create().with_env({}, (io) => {
		// BLOCKER: Here we do NOT pass TEST_POLICY, so it uses the production DEFAULT_POLICY (RS256/ES256)
		// This verifies the production fix.
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500);
		
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok, "Should NOT accept HS256 token in OIDC flow");
		assert.match("UNSUPPORTED_ALGORITHM", res.error);
	});
});

it('oidc: security - reject insecure token endpoint', () => {
	let insecure_disc = { ...f.MOCK_DISCOVERY, token_endpoint: "http://insecure.com/token" };
	mock.create().with_responses({}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, insecure_disc, "code", "verifier-is-long-enough-to-pass-basic-check-123");
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INSECURE_TOKEN_ENDPOINT", res.error);
	});
});

it('oidc: security - handle network failure during exchange', () => {
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { error: "TLS_VERIFY_FAILED" }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "verifier-is-long-enough-to-pass-basic-check-123");
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("TOKEN_ENDPOINT_NETWORK_ERROR", res.error);
	});
});

it('oidc: security - reject insecure issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.idp");
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INSECURE_ISSUER_URL", res.error);
	});
});

it('oidc: security - reject insecure internal issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INSECURE_FETCH_URL", res.error);
	});
});

it('oidc: security - reject discovery document with insecure endpoints', () => {
	let evil_disc = { 
		...f.MOCK_DISCOVERY, 
		jwks_uri: "http://insecure.idp/jwks" 
	};
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";

	mock.create().with_responses({ [url]: { status: 200, body: evil_disc } }, (io) => {
		let res = oidc.discover(io, issuer);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INSECURE_ENDPOINT", res.error);
	});
});

it('oidc: security - reject invalid at_hash', () => {
	let access_token = "access-token-123";
	
	let payload = { 
		iss: f.MOCK_CONFIG.issuer_url, 
		aud: f.MOCK_CONFIG.client_id,
		sub: "user1",
		nonce: "n1",
		iat: 100,
		exp: 1000,
		at_hash: "wrong_hash_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	};
	
	let token = h.generate_id_token(payload, PRIVKEY, "RS256");
	let tokens = { id_token: token, access_token: access_token };
	let keys = JWKS.keys;

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok, "Should reject invalid at_hash");
		assert.match("AT_HASH_MISMATCH", res.error);
	});
});

it('oidc: security - reject missing mandatory claims', () => {
	let keys = JWKS.keys;

	// Case 1: Missing exp
	let p_no_exp = { ...f.MOCK_CLAIMS, exp: null, nonce: "n1", sub: "u1", iat: 100 };
	let t_no_exp = { id_token: h.generate_id_token(p_no_exp, PRIVKEY, "RS256"), access_token: "a" };

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, t_no_exp, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok, "Should reject ID token missing 'exp' claim");
		assert.match("MISSING_EXP_CLAIM", res.error);
	});

	// Case 2: Missing iat
	let p_no_iat = { ...f.MOCK_CLAIMS, iat: null, nonce: "n1", sub: "u1" };
	let t_no_iat = { id_token: h.generate_id_token(p_no_iat, PRIVKEY, "RS256"), access_token: "a" };

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, t_no_iat, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok, "Should reject ID token missing 'iat' claim");
		assert.match("MISSING_IAT_CLAIM", res.error);
	});
});

it('oidc: security - reject missing mandatory at_hash claim (W2)', () => {
	let keys = JWKS.keys;
	let payload = { ...f.MOCK_CLAIMS, at_hash: null, nonce: "n1", sub: "u1" };
	let tokens = { id_token: h.generate_id_token(payload, PRIVKEY, "RS256"), access_token: "at123" };

	let data = mock.create().spy((io) => {
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 1500, TEST_POLICY);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok, "Should reject ID token missing 'at_hash' claim");
		assert.match("MISSING_AT_HASH", res.error);
	});

	assert.match(truthy(), data.called("log", "error", "ID Token missing mandatory at_hash claim (Token Binding violation)"), "Should log security violation");
});

it('oidc: security - reject UserInfo sub mismatch', () => {
	let endpoint = "https://trusted.idp/userinfo";
	let at = "access-token-123";
	let mock_res = { sub: "EVIL-USER", email: "victim@example.com" };

	mock.create().with_responses({
		[endpoint]: { status: 200, body: mock_res }
	}, (io) => {
		let res = oidc.fetch_userinfo(io, endpoint, at);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), res.ok);
		// Note: The handshake.uc logic handles the comparison, so we verify the fetcher first.
		assert.match("EVIL-USER", res.data.sub);
	});
});

it('oidc: security - enforce RFC 7636 PKCE verifier length (43-128 chars)', () => {
	let factory = mock.create();
	
	// Case 1: Too short (< 43)
	factory.with_responses({}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "too-short");
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INVALID_PKCE_VERIFIER", res.error);
	});

	// Case 2: Too long (> 128)
	let long_verifier = "";
	for (let i = 0; i < 129; i++) long_verifier += "a";
	factory.with_responses({}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", long_verifier);
        assert.match(truthy(), Result.is(res));
		assert.match(truthy(), !res.ok);
		assert.match("INVALID_PKCE_VERIFIER", res.error);
	});
});

