import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';
import * as h from 'unit.helpers';

const SECRET = "tier2-logic-test-secret-32-bytes-!";

// =============================================================================
// Tier 2: OIDC Business Logic (Platinum Suite)
// =============================================================================

test('LOGIC: Discovery - Successful Fetch & Schema', () => {
	let mocked = mock.create();
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	mocked.with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(res.ok);
		assert_eq(res.data.issuer, f.MOCK_DISCOVERY.issuer);
	});
});

test('LOGIC: Discovery - Handle Non-JSON Response', () => {
	let mocked = mock.create();
	let issuer = "https://broken.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	// Simulate proxy error returning HTML instead of JSON
	mocked.with_responses({ [url]: { status: 200, body: "<html>Error</html>" } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "INVALID_DISCOVERY_DOC");
	});
});

test('LOGIC: Discovery - Reject Issuer Mismatch', () => {
	let mocked = mock.create();
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

	mocked.with_responses({ [url]: { status: 200, body: evil_doc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "DISCOVERY_ISSUER_MISMATCH");
	});
});

test('LOGIC: Discovery - Cache Robustness & TTL', () => {
	let mocked = mock.create();
	let issuer = "https://trusted.idp";
	let cache_path = "/var/run/luci-sso/oidc-cache-test.json";
	let url = issuer + "/.well-known/openid-configuration";
	
	mocked.with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		oidc.discover(io, issuer, { cache_path: cache_path, ttl: 100 });
		
		mocked.using(io).with_responses({}, (io_cache) => {
			let res = oidc.discover(io_cache, issuer, { cache_path: cache_path, ttl: 100 });
			assert(res.ok, "Should hit cache");
		});

		let data = mocked.using(io).spy((spying_io) => {
			oidc.discover(spying_io, issuer, { cache_path: cache_path, ttl: -1 }); 
		});
		assert(data.called("http_get", url), "Should have attempted network refresh");
	});
});

test('LOGIC: Token - Successful Exchange', () => {
	let mocked = mock.create();
	mocked.with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: {
			status: 200,
			body: { access_token: "mock-access", id_token: "mock-id" }
		}
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code123", "verifier123");
		assert(res.ok);
	});
});

test('LOGIC: Token - Handle IdP Errors (401/400)', () => {
	let mocked = mock.create();
	
	// 1. Unauthorized (401)
	mocked.with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 401, body: { error: "invalid_client" } }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "v");
		assert(!res.ok);
		assert_eq(res.error, "TOKEN_EXCHANGE_FAILED");
	});

	// 2. Bad Request (400)
	mocked.with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "v");
		assert(!res.ok);
	});
});

test('LOGIC: Verification - Support Multi-Audience Arrays', () => {
	let mocked = mock.create();
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	// 1. Success: Correct ID in array
	let payload = { iss: f.MOCK_CONFIG.issuer_url, aud: [ f.MOCK_CONFIG.client_id, "other" ], sub: "u1", exp: 2000000000 };
	let token = h.generate_id_token(payload, SECRET);
	mocked.with_env({}, (io) => {
		assert(oidc.verify_id_token(io, { id_token: token }, keys, { ...f.MOCK_CONFIG, clock_tolerance: 300 }, {}, f.MOCK_DISCOVERY).ok);
	});

	// 2. Failure: Wrong ID in array
	payload.aud = [ "wrong-app-1", "wrong-app-2" ];
	token = h.generate_id_token(payload, SECRET);
	mocked.with_env({}, (io) => {
		let res = oidc.verify_id_token(io, { id_token: token }, keys, { ...f.MOCK_CONFIG, clock_tolerance: 300 }, {}, f.MOCK_DISCOVERY);
		assert_eq(res.error, "AUDIENCE_MISMATCH");
	});

	// 3. Failure: Empty array
	payload.aud = [];
	token = h.generate_id_token(payload, SECRET);
	mocked.with_env({}, (io) => {
		let res = oidc.verify_id_token(io, { id_token: token }, keys, { ...f.MOCK_CONFIG, clock_tolerance: 300 }, {}, f.MOCK_DISCOVERY);
		assert_eq(res.error, "INVALID_AUDIENCE");
	});
});

test('LOGIC: Verification - Reject Expired ID Token', () => {
	let mocked = mock.create();
	let payload = { iss: f.MOCK_CONFIG.issuer_url, sub: "user1", exp: 1500 }; 
	let token = h.generate_id_token(payload, SECRET);
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	mocked.with_env({}, (io) => {
		let res = oidc.verify_id_token(io, { id_token: token }, keys, { ...f.MOCK_CONFIG, clock_tolerance: 300 }, {}, f.MOCK_DISCOVERY);
		assert_eq(res.error, "TOKEN_EXPIRED");
	});
});

test('LOGIC: Verification - Handle Binary Garbage', () => {
	let mocked = mock.create();
	let keys = [ { kty: "oct", k: crypto.b64url_encode(SECRET) } ];
	
	mocked.with_env({}, (io) => {
		let res = oidc.verify_id_token(io, { id_token: "not.a.token" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY);
		assert(!res.ok);
		
		res = oidc.verify_id_token(io, { id_token: "\x00\xff\xdeadbeef" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY);
		assert(!res.ok);
	});
});

test('LOGIC: JWKS - Successful Fetch, Cache & TTL', () => {
	let mocked = mock.create();
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-cache-test.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mocked.with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io) => {
		let res = oidc.fetch_jwks(io, jwks_uri, { cache_path: cache_path, ttl: 3600 });
		assert(res.ok);
		assert_eq(res.data[0].kid, "k1");
		
		mocked.using(io).with_responses({}, (io_cache) => {
			let res2 = oidc.fetch_jwks(io_cache, jwks_uri, { cache_path: cache_path, ttl: 3600 });
			assert(res2.ok, "Should hit cache");
		});
	});
});

test('TORTURE: JWKS - Handle Corrupted Cache', () => {
	let mocked = mock.create();
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-corrupt.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mocked.with_files({ [cache_path]: "{ invalid json !!! }" }, (io) => {
		mocked.using(io).with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io_final) => {
			let res = oidc.fetch_jwks(io_final, jwks_uri, { cache_path: cache_path });
			assert(res.ok, "Should fall back to network if cache is corrupted");
			assert_eq(res.data[0].kid, "k1");
		});
	});
});

test('LOGIC: Discovery - Immutable Cache (No Pollution)', () => {
	let mocked = mock.create();
	let issuer = "https://public.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let mock_disc = { 
		issuer: issuer,
		authorization_endpoint: issuer + "/auth",
		token_endpoint: issuer + "/token",
		jwks_uri: issuer + "/jwks"
	};
	
	mocked.with_responses({ [url]: { status: 200, body: mock_disc } }, (io) => {
		let res1 = oidc.discover(io, issuer);
		assert(res1.ok);
		res1.data.token_endpoint = "http://EVIL";
		
		let res2 = oidc.discover(io, issuer);
		assert_eq(res2.data.token_endpoint, issuer + "/token", "Cache must not be polluted");
	});
});