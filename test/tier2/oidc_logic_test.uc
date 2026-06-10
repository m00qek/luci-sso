import { it, assert, truthy, falsy } from 'utest';
import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as encoding from 'luci_sso.encoding';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

const PRIVKEY = f.MOCK_PRIVKEY;
const JWKS = { keys: [ f.MOCK_JWK ] };
const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

function make_oidc_deps(io) {
	return {
		http: {
			get:  (url, opts) => io.http_get(url, opts),
			post: (url, opts) => io.http_post(url, opts)
		},
		log: io.log
	};
}

// =============================================================================
// Tier 2: OIDC Business Logic (Platinum Refactor)
// =============================================================================

it('oidc: discovery - successful fetch & schema', () => {
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert.match(truthy(), res.ok);
		assert.match(f.MOCK_DISCOVERY.issuer, res.data.issuer);
	});
});

it('oidc: discovery - handle non-JSON response', () => {
	let issuer = "https://broken.idp";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: "<html>Error</html>" } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert.match(falsy(), res.ok);
		assert.match("INVALID_DISCOVERY_DOC", res.error);
	});
});

it('oidc: discovery - reject issuer mismatch', () => {
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

	mock.create().with_responses({ [url]: { status: 200, body: evil_doc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert.match(falsy(), res.ok);
		assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
	});
});

it('oidc: discovery - reject document missing issuer field', () => {
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";
	let bad_doc = { ...f.MOCK_DISCOVERY };
	delete bad_doc.issuer;

	mock.create().with_responses({ [url]: { status: 200, body: bad_doc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert.match(falsy(), res.ok, "Should fail if issuer field is missing");
		assert.match("DISCOVERY_MISSING_ISSUER", res.error);
	});
});

it('oidc: discovery - cache robustness & TTL', () => {
	let issuer = "https://trusted.idp";
	let cache_path = "/var/run/luci-sso/oidc-cache-test.json";
	let url = issuer + "/.well-known/openid-configuration";
	
	mock.create().with_responses({ [url]: { status: 200, body: f.MOCK_DISCOVERY } }, (io) => {
		oidc.discover(io, issuer, { cache_path: cache_path, ttl: 100 });
		
		mock.create().using(io).with_responses({}, (io_cache) => {
			let res = oidc.discover(io_cache, issuer, { cache_path: cache_path, ttl: 100 });
			assert.match(truthy(), res.ok, "Should hit cache");
		});

		let data = mock.create().using(io).spy((spying_io) => {
			oidc.discover(spying_io, issuer, { cache_path: cache_path, ttl: -1 }); 
		});
		assert.match(truthy(), data.called("http_get", url), "Should have attempted network refresh");
	});
});

it('oidc: token - successful exchange', () => {
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: {
			status: 200,
			body: { access_token: "mock-access", id_token: "mock-id" }
		}
	}, (io) => {
		let res = oidc.exchange_code(make_oidc_deps(io), f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code123", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
		assert.match(truthy(), res.ok);
	});
});

it('oidc: token - handle IdP errors (401/400)', () => {
	let v = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";
	// 1. Unauthorized (401)
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 401, body: { error: "invalid_client" } }
	}, (io) => {
		let res = oidc.exchange_code(make_oidc_deps(io), f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert.match(falsy(), res.ok);
		assert.match("TOKEN_EXCHANGE_FAILED", res.error);
	});

	// 2. Bad Request (400) - Generic
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "something_else" } }
	}, (io) => {
		let res = oidc.exchange_code(make_oidc_deps(io), f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert.match(falsy(), res.ok);
		assert.match("TOKEN_EXCHANGE_FAILED", res.error);
	});

	// 3. Bad Request (400) - Specific invalid_grant
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } }
	}, (io) => {
		let res = oidc.exchange_code(make_oidc_deps(io), f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
		assert.match(falsy(), res.ok);
		assert.match("OIDC_INVALID_GRANT", res.error);
	});
});

it('oidc: ID token - support multi-audience arrays', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
	
	// 1. Success: Correct ID in array
	// RFC 7519: If aud is array, azp is mandatory.
	let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], azp: f.MOCK_CONFIG.client_id, at_hash: ah };
	let token = h.generate_id_token(payload, PRIVKEY, "RS256");
	mock.create().with_env({}, (io) => {
		assert.match(truthy(), oidc.verify_id_token(make_oidc_deps(io), { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY).ok);
	});

	// 2. Failure: Wrong ID in array
	payload.aud = [ "wrong-app-1", "wrong-app-2" ];
	token = h.generate_id_token(payload, PRIVKEY, "RS256");
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("AUDIENCE_MISMATCH", res.error);
	});

	// 3. Failure: Empty array
	payload.aud = [];
	token = h.generate_id_token(payload, PRIVKEY, "RS256");
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("INVALID_AUDIENCE", res.error);
	});
});

it('oidc: ID token - support AZP claim', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
	let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], at_hash: ah };

	mock.create().with_env({}, (io) => {
		// 1. Mismatched AZP
		payload.azp = "evil-app";
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("AZP_MISMATCH", res.error);

		// 2. Correct AZP
		payload.azp = f.MOCK_CONFIG.client_id;
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		assert.match(truthy(), oidc.verify_id_token(make_oidc_deps(io), { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY).ok);

		// 3. Blocker #5: Universal AZP (Single audience with mismatched AZP)
		payload.aud = f.MOCK_CONFIG.client_id;
		payload.azp = "mismatched-client";
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("AZP_MISMATCH", res.error, "AZP must match even for single audience");
	});
});

it('oidc: ID token - reject expired ID token', () => {
	let payload = { ...f.MOCK_CLAIMS, exp: 1500 }; 
	let token = h.generate_id_token(payload, PRIVKEY, "RS256");
	let keys = JWKS.keys;
	
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("TOKEN_EXPIRED", res.error);
	});
});

it('oidc: ID token - enforce nonce matching', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
	let payload = { ...f.MOCK_CLAIMS, at_hash: ah };
	let token = h.generate_id_token(payload, PRIVKEY, "RS256");
	
	mock.create().with_env({}, (io) => {
		// 1. Success
		let handshake = { nonce: "n" };
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(truthy(), res.ok);
		
		// 2. Mismatch
		handshake.nonce = "different-nonce";
		res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("NONCE_MISMATCH", res.error);

		// 3. Missing from token
		delete payload.nonce;
		let token_no_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
		res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token_no_nonce, access_token: at }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("MISSING_NONCE", res.error);

		// 4. Missing from handshake
		payload.nonce = "n";
		let token_with_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
		res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token_with_nonce, access_token: at }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("MISSING_NONCE", res.error);
	});
});

it('oidc: ID token - handle binary garbage', () => {
	let keys = JWKS.keys;
	
	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: "not.a.token" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(falsy(), res.ok);
		
		res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: "\x00\xff\xdeadbeef" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(falsy(), res.ok);
	});
});

it('oidc: JWKS - successful fetch, cache & TTL', () => {
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-cache-test.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mock.create().with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io) => {
		let res = oidc.fetch_jwks(io, jwks_uri, { cache_path: cache_path, ttl: 3600 });
		assert.match(truthy(), res.ok);
		assert.match("k1", res.data[0].kid);
		
		mock.create().using(io).with_responses({}, (io_cache) => {
			let res2 = oidc.fetch_jwks(io_cache, jwks_uri, { cache_path: cache_path, ttl: 3600 });
			assert.match(truthy(), res2.ok, "Should hit cache");
		});
	});
});

it('oidc: JWKS - handle corrupted cache', () => {
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/jwks-corrupt.json";
	let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
	
	mock.create().with_files({ [cache_path]: "{ invalid json !!! }" }, (io) => {
		mock.create().using(io).with_responses({ [jwks_uri]: { status: 200, body: mock_jwks } }, (io_final) => {
			let res = oidc.fetch_jwks(io_final, jwks_uri, { cache_path: cache_path });
			assert.match(truthy(), res.ok, "Should fall back to network if cache is corrupted");
			assert.match("k1", res.data[0].kid);
		});
	});
});

it('oidc: token - enforce PKCE verifier length', () => {
	mock.create().with_responses({}, (io) => {
		// 1. Weak verifier
		let res = oidc.exchange_code(make_oidc_deps(io),f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "weak");
		assert.match(falsy(), res.ok);
		assert.match("INVALID_PKCE_VERIFIER", res.error);

		// 2. Valid verifier
		mock.create().using(io).with_responses({
			[f.MOCK_DISCOVERY.token_endpoint]: {
				status: 200,
				body: { access_token: "a", id_token: "i" }
			}
		}, (io_ok) => {
			let long_verifier = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";
			let res_ok = oidc.exchange_code(make_oidc_deps(io_ok), f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", long_verifier);
			assert.match(truthy(), res_ok.ok);
		});
	});
});

it('oidc: ID token - at_hash validation ensures token binding', () => {
	let access_token = "valid-access-token-123";
	let keys = JWKS.keys;
	
	let full_hash = crypto.hash_sha256(access_token).data;
	let left_half = encoding.binary_truncate(full_hash, 16).data;
	let correct_hash = encoding.b64url_encode(left_half).data;

	mock.create().with_env({}, (io) => {
		// 1. Success: at_hash matches access_token
		let p1 = { ...f.MOCK_CLAIMS, at_hash: correct_hash };
		let res1 = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token: access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(truthy(), res1.ok, "Should accept matching at_hash");

		// 2. Failure: Both missing (Stripping Attack / Hybrid Bypass)
		let p2 = { ...f.MOCK_CLAIMS };
		let res2 = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p2, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("MISSING_ACCESS_TOKEN", !res2.ok && res2.error, "Should fail if access_token is missing");

		// 3. Failure: at_hash does not match access_token
		let res3 = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token: "wrong" }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("AT_HASH_MISMATCH", !res3.ok && res3.error);

		// 4. Failure: at_hash missing when access_token present
		let res4 = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p2, PRIVKEY, "RS256"), access_token: access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("MISSING_AT_HASH", !res4.ok && res4.error);

		// 5. Failure: at_hash present but access_token missing (Stripping Attack)
		let res5 = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p1, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match("MISSING_ACCESS_TOKEN", !res5.ok && res5.error);
	});
});

it('oidc: ID token - at_hash validation byte-safety torture', () => {
	// "at-hash-torture-input-1" produces a SHA256 hash starting with 0xc2
	// 0xc2 is the first byte of a multi-byte UTF-8 sequence. 
	// If substr() is used on the raw string, it might try to parse it as UTF-8.
	let access_token = "at-hash-torture-input-1";
	let keys = JWKS.keys;
	
	let full_hash = crypto.hash_sha256(access_token).data;
	
	// Manually construct the left-half correctly (raw bytes)
	let left_half = encoding.binary_truncate(full_hash, 16).data;
	let correct_at_hash = encoding.b64url_encode(left_half).data;

	mock.create().with_env({}, (io) => {
		let p = { ...f.MOCK_CLAIMS, at_hash: correct_at_hash };
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: h.generate_id_token(p, PRIVKEY, "RS256"), access_token: access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		
		assert.match(truthy(), res.ok, "at_hash validation MUST be byte-safe (failed for binary sequence)");
	});
});

it('oidc: discovery - immutable cache (no pollution)', () => {
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
		assert.match(truthy(), res1.ok);
		res1.data.token_endpoint = "http://EVIL";
		
		let res2 = oidc.discover(io, issuer);
		assert.match(issuer + "/token", res2.data.token_endpoint, "Cache must not be polluted");
	});
});

it('oidc: discovery - handle insecure end_session_endpoint', () => {
	let factory = mock.create();
	let disc = { 
		issuer: "https://idp.com", 
		authorization_endpoint: "https://idp.com/auth",
		token_endpoint: "https://idp.com/token",
		jwks_uri: "https://idp.com/jwks",
		end_session_endpoint: "http://insecure.com/logout"
	};
	
	factory.with_responses({ "https://idp.com/.well-known/openid-configuration": { status: 200, body: disc } }, (io) => {
		let res = oidc.discover(io, "https://idp.com");
		assert.match(truthy(), res.ok);
		assert.match(falsy(), res.data.end_session_endpoint, "Insecure end_session_endpoint MUST be removed");
	});
});

it('oidc: encoding - parameter torture test', () => {
	let factory = mock.create();
	let complex_config = {
		...f.MOCK_CONFIG,
		client_id: "app & user",
		redirect_uri: "https://router.lan/callback?param=1&other=2"
	};
	let params = {
		state: "state with spaces & symbols #1_long_enough",
		nonce: "nonce+plus+long+enough+for+validation",
		code_challenge: "challenge/slash"
	};

	// 1. Verify Authorization URL Encoding
	let res = oidc.get_auth_url(null, complex_config, f.MOCK_DISCOVERY, params);
	assert.match(truthy(), res.ok, "get_auth_url should succeed");
	let url = res.data;
	
	assert.match(truthy(), index(url, "client_id=app%20%26%20user") != -1, "client_id must be encoded");
	assert.match(truthy(), index(url, "redirect_uri=https%3A%2F%2Frouter.lan%2Fcallback%3Fparam%3D1%26other%3D2") != -1, "redirect_uri must be fully encoded");
	assert.match(truthy(), index(url, "state=state%20with%20spaces%20%26%20symbols%20%231_long_enough") != -1, "state must be encoded");

	// 2. Verify Token Exchange Body Encoding
	let data = factory.spy((io) => {
		factory.using(io).with_responses({
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 200, body: {} }
		}, (io_http) => {
			oidc.exchange_code(make_oidc_deps(io_http), complex_config, f.MOCK_DISCOVERY, "code & space", "verifier/slash-that-is-at-least-43-chars-long-!!!", "s1");
		});
	});

	let post_call = null;
	for (let entry in data.all()) {
		if (entry.type == "http_post") {
			post_call = entry;
			break;
		}
	}

	assert.match(truthy(), post_call, "Should have made an HTTP POST call");
	let body = post_call.args[1].body;
	assert.match(truthy(), index(body, "code=code%20%26%20space") != -1, "code in body must be encoded");
	assert.match(truthy(), index(body, "code_verifier=verifier%2Fslash-that-is-at-least-43-chars-long-!!!") != -1, "verifier in body must be encoded");
});

it('oidc: userinfo - successful fetch', () => {
	let endpoint = "https://trusted.idp/userinfo";
	let at = "access-token-123";
	let mock_res = { sub: "user-123", email: "user@example.com" };

	mock.create().with_responses({
		[endpoint]: { status: 200, body: mock_res }
	}, (io) => {
		let res = oidc.fetch_userinfo(make_oidc_deps(io), endpoint, at);
		assert.match(truthy(), res.ok);
		assert.match("user@example.com", res.data.email);
	});
});

it('oidc: userinfo - reject missing sub claim', () => {
	let endpoint = "https://trusted.idp/userinfo";
	mock.create().with_responses({
		[endpoint]: { status: 200, body: { email: "no-sub@example.com" } }
	}, (io) => {
		let res = oidc.fetch_userinfo(make_oidc_deps(io), endpoint, "at");
		assert.match(falsy(), res.ok);
		assert.match("MISSING_SUB_CLAIM", res.error);
	});
});

it('oidc: ID token - require azp when aud has multiple audiences', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;

	// OIDC Core 1.0 §3.1.3.7 item 4: "If the ID Token contains multiple
	// audiences, the Client SHOULD verify that an azp Claim is present."
	let payload = {
		...f.MOCK_CLAIMS,
		aud: [ f.MOCK_CONFIG.client_id, "other-service" ],
		at_hash: ah
	};
	delete payload.azp;

	let token = h.generate_id_token(payload, PRIVKEY, "RS256");

	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(falsy(), res.ok, "Verification MUST fail when aud has multiple audiences but azp is missing");
		assert.match("MISSING_AZP_CLAIM", res.error);
	});
});

it('oidc: ID token - accept single-element aud array without azp', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;

	// OIDC Core 1.0 §3.1.3.7 item 4 only triggers for MULTIPLE audiences.
	// An aud array with a single element is logically single-audience.
	let payload = {
		...f.MOCK_CLAIMS,
		aud: [ f.MOCK_CONFIG.client_id ],
		at_hash: ah
	};
	delete payload.azp;

	let token = h.generate_id_token(payload, PRIVKEY, "RS256");

	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(truthy(), res.ok, `Verification MUST succeed for single-element aud array without azp (Error: ${res.error})`);
	});
});

it('oidc: ID token - reject azp mismatch even for single-element aud', () => {
	let keys = JWKS.keys;
	let at = "mock-at";
	let full_hash = crypto.hash_sha256(at).data;
	let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;

	// OIDC Core 1.0 §3.1.3.7 item 5: "If an azp Claim is present, the Client
	// SHOULD verify that its client_id is the Claim Value."
	let payload = {
		...f.MOCK_CLAIMS,
		aud: [ f.MOCK_CONFIG.client_id ],
		azp: "malicious-client",
		at_hash: ah
	};

	let token = h.generate_id_token(payload, PRIVKEY, "RS256");

	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(make_oidc_deps(io),{ id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert.match(falsy(), res.ok, "Verification MUST fail when azp claim is present but mismatched");
		assert.match("AZP_MISMATCH", res.error);
	});
});
