import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';
import * as h from 'unit.helpers';

const SECRET = "tier2-logic-test-secret-32-bytes-!";

// =============================================================================
// Tier 2: OIDC Business Logic (Platinum Refactor)
// =============================================================================

test('OIDC: Discovery - Successful Fetch & Schema', () => {
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(res.ok);
		assert_eq(res.data.issuer, f.MOCK_DISCOVERY.issuer);
	});
});

test('OIDC: Discovery - Handle Non-JSON Response', () => {
	let issuer = "https://broken.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: "<html>Error</html>" } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "INVALID_DISCOVERY_DOC");
	});
});

test('OIDC: Discovery - Reject Issuer Mismatch', () => {
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

	mock.create().with_responses({ [url]: { status: 200, body: evil_doc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "DISCOVERY_ISSUER_MISMATCH");
	});
});

test('OIDC: Discovery - Cache Robustness & TTL', () => {
	let issuer = "https://trusted.idp";
	let cache_path = "/var/run/luci-sso/oidc-cache-test.json";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		oidc.discover(io, issuer, { cache_path: cache_path, ttl: 100 });
		
		mock.create().using(io).with_responses({}, (io_cache) => {
			let res = oidc.discover(io_cache, issuer, { cache_path: cache_path, ttl: 100 });
			assert(res.ok, "Should hit cache");
		});

		let data = mock.create().using(io).spy((spying_io) => {
			oidc.discover(spying_io, issuer, { cache_path: cache_path, ttl: -1 }); 
		});
		assert(data.called("http_get", url), "Should have attempted network refresh");
	});
});

test('OIDC: Token - Successful Exchange', () => {
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: {
			status: 200,
			body: { access_token: "mock-access", id_token: "mock-id" }
		}
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code123", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
		assert(res.ok);
	});
});

test('OIDC: Token - Handle IdP Errors (401/400)', () => {
	let v = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";
	// 1. Unauthorized (401)
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 401, body: { error: "invalid_client" } }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert(!res.ok);
		assert_eq(res.error, "TOKEN_EXCHANGE_FAILED");
	});

	// 2. Bad Request (400) - Generic
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "something_else" } }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert(!res.ok);
		assert_eq(res.error, "TOKEN_EXCHANGE_FAILED");
	});

	// 3. Bad Request (400) - Specific invalid_grant
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert(!res.ok);
		assert_eq(res.error, "OIDC_INVALID_GRANT");
	});
});

test('OIDC: ID Token - Support Multi-Audience Arrays', () => {
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	let at = "mock-at";
	let full_hash = crypto.sha256(at);
	let ah = crypto.b64url_encode(substr(full_hash, 0, 16));
	
	// 1. Success: Correct ID in array
	let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], at_hash: ah };
	let token = h.generate_id_token(payload, SECRET);
	mock.create().with_env({}, (io) => {
		assert(oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time()).ok);
	});

	// 2. Failure: Wrong ID in array
	payload.aud = [ "wrong-app-1", "wrong-app-2" ];
	token = h.generate_id_token(payload, SECRET);
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "AUDIENCE_MISMATCH");
	});

	// 3. Failure: Empty array
	payload.aud = [];
	token = h.generate_id_token(payload, SECRET);
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "INVALID_AUDIENCE");
	});
});

test('OIDC: ID Token - Support AZP Claim', () => {
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	let at = "mock-at";
	let full_hash = crypto.sha256(at);
	let ah = crypto.b64url_encode(substr(full_hash, 0, 16));
	let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], at_hash: ah };

	mock.create().with_env({}, (io) => {
		// 1. Mismatched AZP
		payload.azp = "evil-app";
		let token = h.generate_id_token(payload, SECRET);
		let res = oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "AZP_MISMATCH");

		// 2. Correct AZP
		payload.azp = f.MOCK_CONFIG.client_id;
		token = h.generate_id_token(payload, SECRET);
		assert(oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time()).ok);
	});
});

test('OIDC: ID Token - Reject Expired ID Token', () => {
	let payload = { ...f.MOCK_CLAIMS, exp: 1500 }; 
	let token = h.generate_id_token(payload, SECRET);
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token({ id_token: token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "TOKEN_EXPIRED");
	});
});

test('OIDC: ID Token - Enforce Nonce Matching', () => {
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	let at = "mock-at";
	let full_hash = crypto.sha256(at);
	let ah = crypto.b64url_encode(substr(full_hash, 0, 16));
	let payload = { ...f.MOCK_CLAIMS, at_hash: ah };
	let token = h.generate_id_token(payload, SECRET);
	
	mock.create().with_env({}, (io) => {
		// 1. Success
		let handshake = { nonce: "n" };
		let res = oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time());
		assert(res.ok);
		
		// 2. Mismatch
		handshake.nonce = "different-nonce";
		res = oidc.verify_id_token({ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "NONCE_MISMATCH");

		// 3. Missing from token
		delete payload.nonce;
		let token_no_nonce = h.generate_id_token(payload, SECRET);
		res = oidc.verify_id_token({ id_token: token_no_nonce, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "MISSING_NONCE");

		// 4. Missing from handshake
		payload.nonce = "n";
		let token_with_nonce = h.generate_id_token(payload, SECRET);
		res = oidc.verify_id_token({ id_token: token_with_nonce, access_token: at }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time());
		assert_eq(res.error, "MISSING_NONCE");
	});
});

test('OIDC: ID Token - Handle Binary Garbage', () => {
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token({ id_token: "not.a.token" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time());
		assert(!res.ok);
		
		res = oidc.verify_id_token({ id_token: "\x00\xff\xdeadbeef" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time());
		assert(!res.ok);
	});
});

test('OIDC: JWKS - Successful Fetch, Cache & TTL', () => {
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-cache-test.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mock.create().with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io) => {
		let res = oidc.fetch_jwks(io, jwks_uri, { cache_path: cache_path, ttl: 3600 });
		assert(res.ok);
		assert_eq(res.data[0].kid, "k1");
		
		mock.create().using(io).with_responses({}, (io_cache) => {
			let res2 = oidc.fetch_jwks(io_cache, jwks_uri, { cache_path: cache_path, ttl: 3600 });
			assert(res2.ok, "Should hit cache");
		});
	});
});

test('OIDC: JWKS - Handle Corrupted Cache', () => {
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-corrupt.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mock.create().with_files({ [cache_path]: "{ invalid json !!! }" }, (io) => {
		mock.create().using(io).with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io_final) => {
			let res = oidc.fetch_jwks(io_final, jwks_uri, { cache_path: cache_path });
			assert(res.ok, "Should fall back to network if cache is corrupted");
			assert_eq(res.data[0].kid, "k1");
		});
	});
});

test('OIDC: Token - Enforce PKCE Verifier Length', () => {
	mock.create().with_responses({}, (io) => {
		// 1. Weak verifier
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "weak");
		assert(!res.ok);
		assert_eq(res.error, "INVALID_PKCE_VERIFIER");

		// 2. Valid verifier
		mock.create().using(io).with_responses({
			[f.MOCK_DISCOVERY.token_endpoint]: {
				status: 200,
				body: { access_token: "a", id_token: "i" }
			}
		}, (io_ok) => {
			let long_verifier = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";
			let res_ok = oidc.exchange_code(io_ok, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", long_verifier);
			assert(res_ok.ok);
		});
	});
});

test('OIDC: ID Token - at_hash validation ensures token binding', () => {
	let access_token = "valid-access-token-123";
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	let full_hash = crypto.sha256(access_token);
	let left_half = substr(full_hash, 0, 16);
	let correct_hash = crypto.b64url_encode(left_half);

	mock.create().with_env({}, (io) => {
		// 1. Success: at_hash matches access_token
		let p1 = { ...f.MOCK_CLAIMS, at_hash: correct_hash };
		let res1 = oidc.verify_id_token({ id_token: h.generate_id_token(p1, SECRET), access_token: access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert(res1.ok, "Should accept matching at_hash");

		// 2. Failure: Both missing (Stripping Attack / Hybrid Bypass)
		let p2 = { ...f.MOCK_CLAIMS };
		let res2 = oidc.verify_id_token({ id_token: h.generate_id_token(p2, SECRET) }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert(!res2.ok && res2.error == "MISSING_ACCESS_TOKEN", "Should fail if access_token is missing");

		// 3. Failure: at_hash does not match access_token
		let res3 = oidc.verify_id_token({ id_token: h.generate_id_token(p1, SECRET), access_token: "wrong" }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert(!res3.ok && res3.error == "AT_HASH_MISMATCH");

		// 4. Failure: at_hash missing when access_token present
		let res4 = oidc.verify_id_token({ id_token: h.generate_id_token(p2, SECRET), access_token: access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert(!res4.ok && res4.error == "MISSING_AT_HASH");

		// 5. Failure: at_hash present but access_token missing (Stripping Attack)
		let res5 = oidc.verify_id_token({ id_token: h.generate_id_token(p1, SECRET) }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time());
		assert(!res5.ok && res5.error == "MISSING_ACCESS_TOKEN");
	});
});

test('OIDC: Discovery - Immutable Cache (No Pollution)', () => {
	let issuer = "https://public.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let mock_disc = { 
		issuer: issuer,
		authorization_endpoint: issuer + "/auth",
		token_endpoint: issuer + "/token",
		jwks_uri: issuer + "/jwks"
	};
	
	mock.create().with_responses({ [url]: { status: 200, body: mock_disc } }, (io) => {
		let res1 = oidc.discover(io, issuer);
		assert(res1.ok);
		res1.data.token_endpoint = "http://EVIL";
		
		let res2 = oidc.discover(io, issuer);
		assert_eq(res2.data.token_endpoint, issuer + "/token", "Cache must not be polluted");
	});
});