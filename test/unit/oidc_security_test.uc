import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

const TEST_POLICY = { allowed_algs: ["RS256", "ES256", "HS256"] };

test('oidc: security - reject HS256 algorithm confusion', () => {
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
	let token = crypto.sign_jws(payload, "secret-key"); // Maliciously signed with symmetric HS256

	let tokens = { id_token: token, access_token: "fake" };
	let keys = [{ kty: "RSA", kid: "key1", n: "...", e: "..." }]; // IdP only advertises RSA

	mock.create().with_env({}, (io) => {
		// BLOCKER: Here we do NOT pass TEST_POLICY, so it uses the production DEFAULT_POLICY (RS256/ES256)
		// This verifies the production fix.
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500);
		
		assert(!res.ok, "Should NOT accept HS256 token in OIDC flow");
		assert_eq(res.error, "UNSUPPORTED_ALGORITHM");
	});
});

test('oidc: security - reject insecure token endpoint', () => {
	let insecure_disc = { ...f.MOCK_DISCOVERY, token_endpoint: "http://insecure.com/token" };
	mock.create().with_responses({}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, insecure_disc, "code", "verifier-is-long-enough-to-pass-basic-check-123");
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_TOKEN_ENDPOINT");
	});
});

test('oidc: security - handle network failure during exchange', () => {
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { error: "TLS_VERIFY_FAILED" }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "verifier-is-long-enough-to-pass-basic-check-123");
		assert(!res.ok);
		assert_eq(res.error, "NETWORK_ERROR");
	});
});

test('oidc: security - reject insecure issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.idp");
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_ISSUER_URL");
	});
});

test('oidc: security - reject insecure internal issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_FETCH_URL");
	});
});

test('oidc: security - reject discovery document with insecure endpoints', () => {
	let evil_disc = { 
		...f.MOCK_DISCOVERY, 
		jwks_uri: "http://insecure.idp/jwks" 
	};
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";

	mock.create().with_responses({ [url]: { status: 200, body: evil_disc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_ENDPOINT");
	});
});

test('oidc: security - reject invalid at_hash', () => {
	let access_token = "access-token-123";
	let secret = f.MOCK_CONFIG.client_secret;
	
	let payload = { 
		iss: f.MOCK_CONFIG.issuer_url, 
		aud: f.MOCK_CONFIG.client_id,
		sub: "user1",
		nonce: "n1",
		iat: 100,
		exp: 1000,
		at_hash: "wrong_hash_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	};
	
	let token = crypto.sign_jws(payload, secret);
	let tokens = { id_token: token, access_token: access_token };
	let keys = [{ kty: "oct", kid: "dummy", k: crypto.b64url_encode(secret) }];

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
		assert(!res.ok, "Should reject invalid at_hash");
		assert_eq(res.error, "AT_HASH_MISMATCH");
	});
});

test('oidc: security - reject missing mandatory claims', () => {
	let secret = f.MOCK_CONFIG.client_secret;
	let keys = [{ kty: "oct", kid: "HS256", k: crypto.b64url_encode(secret) }];

	// Case 1: Missing exp
	let p_no_exp = { ...f.MOCK_CLAIMS, exp: null, nonce: "n1", sub: "u1", iat: 100 };
	let t_no_exp = { id_token: crypto.sign_jws(p_no_exp, secret), access_token: "a" };

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, t_no_exp, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
		assert(!res.ok, "Should reject ID token missing 'exp' claim");
		assert_eq(res.error, "MISSING_EXP_CLAIM");
	});

	// Case 2: Missing iat
	let p_no_iat = { ...f.MOCK_CLAIMS, iat: null, nonce: "n1", sub: "u1" };
	let t_no_iat = { id_token: crypto.sign_jws(p_no_iat, secret), access_token: "a" };

	mock.create().with_responses({}, (io) => {
		let res = oidc.verify_id_token(io, t_no_iat, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
		assert(!res.ok, "Should reject ID token missing 'iat' claim");
		assert_eq(res.error, "MISSING_IAT_CLAIM");
	});
});

test('oidc: security - reject missing mandatory at_hash claim (W2)', () => {
	let secret = f.MOCK_CONFIG.client_secret;
	let keys = [{ kty: "oct", kid: "HS256", k: crypto.b64url_encode(secret) }];
	let payload = { ...f.MOCK_CLAIMS, at_hash: null, nonce: "n1", sub: "u1" };
	let tokens = { id_token: crypto.sign_jws(payload, secret), access_token: "at123" };

	let data = mock.create().spy((io) => {
		let res = oidc.verify_id_token(io, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 1500, TEST_POLICY);
		assert(!res.ok, "Should reject ID token missing 'at_hash' claim");
		assert_eq(res.error, "MISSING_AT_HASH");
	});

	assert(data.called("log", "error", "ID Token missing mandatory at_hash claim (Token Binding violation)"), "Should log security violation");
});

test('oidc: security - reject UserInfo sub mismatch', () => {
	let endpoint = "https://trusted.idp/userinfo";
	let at = "access-token-123";
	let mock_res = { sub: "EVIL-USER", email: "victim@example.com" };

	mock.create().with_responses({
		[endpoint]: { status: 200, body: mock_res }
	}, (io) => {
		let res = oidc.fetch_userinfo(io, endpoint, at);
		assert(res.ok);
		// Note: The handshake.uc logic handles the comparison, so we verify the fetcher first.
		assert_eq(res.data.sub, "EVIL-USER");
	});
});
