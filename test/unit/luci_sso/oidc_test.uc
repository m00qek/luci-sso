import { describe, it, prop, gen, assert, contains, truthy, falsy, spy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

// Real-flow coverage below enters at oidc's exported functions with a faked deps
// graph (with_context builds http+fs+clock+native from proxies). oidc is unit-
// classified; the handshake orchestration halves of the mixed tier2 files live in
// integration/handshake_test.uc.
const PRIVKEY      = f.MOCK_PRIVKEY;
const JWKS         = { keys: [ f.MOCK_JWK ] };
const TEST_POLICY  = { allowed_algs: ["RS256", "ES256"] };

// 16-char minimum for state and nonce
const STATE     = 'AAAAAAAAAAAAAAAA';
const NONCE     = 'BBBBBBBBBBBBBBBB';
const CHALLENGE = 'Uf2O4bYxjIJ1xnEi-6JGCSmKLarh6VjNYsBHMgFT6HI';

const VALID_PARAMS    = { state: STATE, nonce: NONCE, code_challenge: CHALLENGE };
const VALID_DISCOVERY = { authorization_endpoint: 'https://idp.example.com/authorize' };
const VALID_CONFIG    = { client_id: 'client1', redirect_uri: 'https://app.example.com/callback', scope: 'openid' };

const LOG = { log: () => null };

// Builds a minimal fake JWT with a b64url-encoded JSON header for early-exit tests.
function jwt_with_header(header_claims) {
	return encoding.b64url_encode(sprintf('%J', header_claims)).data + '.payload.sig';
}

// ─── get_auth_url ────────────────────────────────────────────────────────────

describe('oidc: get_auth_url', () => {
	it('returns MISSING_STATE_PARAMETER when state is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_STATE_PARAMETER' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { nonce: NONCE, code_challenge: CHALLENGE }));
	});

	it('returns MISSING_STATE_PARAMETER when state is not a string', () => {
		assert.match(contains({ ok: false, error: 'MISSING_STATE_PARAMETER' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: 42, nonce: NONCE, code_challenge: CHALLENGE }));
	});

	it('returns MISSING_STATE_PARAMETER when state is shorter than 16 characters', () => {
		assert.match(contains({ ok: false, error: 'MISSING_STATE_PARAMETER' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: 'tooshort', nonce: NONCE, code_challenge: CHALLENGE }));
	});

	it('returns MISSING_NONCE_PARAMETER when nonce is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_NONCE_PARAMETER' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: STATE, code_challenge: CHALLENGE }));
	});

	it('returns MISSING_NONCE_PARAMETER when nonce is shorter than 16 characters', () => {
		assert.match(contains({ ok: false, error: 'MISSING_NONCE_PARAMETER' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: STATE, nonce: 'tooshort', code_challenge: CHALLENGE }));
	});

	it('returns MISSING_PKCE_CHALLENGE when code_challenge is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_PKCE_CHALLENGE' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: STATE, nonce: NONCE }));
	});

	it('returns MISSING_PKCE_CHALLENGE when code_challenge is not a string', () => {
		assert.match(contains({ ok: false, error: 'MISSING_PKCE_CHALLENGE' }),
			oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, { state: STATE, nonce: NONCE, code_challenge: 42 }));
	});

	it('returns INSECURE_AUTH_ENDPOINT for an http authorization_endpoint', () => {
		assert.match(contains({ ok: false, error: 'INSECURE_AUTH_ENDPOINT' }),
			oidc.get_auth_url(null, VALID_CONFIG, { authorization_endpoint: 'http://idp.example.com/authorize' }, VALID_PARAMS));
	});

	it('returns INVALID_AUTH_ENDPOINT when authorization_endpoint contains a fragment', () => {
		assert.match(contains({ ok: false, error: 'INVALID_AUTH_ENDPOINT' }),
			oidc.get_auth_url(null, VALID_CONFIG, { authorization_endpoint: 'https://idp.example.com/authorize#frag' }, VALID_PARAMS));
	});

	it('returns a URL that includes all required OAuth2 parameters', () => {
		let res = oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY, VALID_PARAMS);
		assert.match(contains({ ok: true }), res);
		assert.match(true, index(res.data, 'state=' + STATE) >= 0);
		assert.match(true, index(res.data, 'nonce=' + NONCE) >= 0);
		assert.match(true, index(res.data, 'code_challenge_method=S256') >= 0);
		assert.match(true, index(res.data, 'response_type=code') >= 0);
	});

	it('uses "openid profile email" as the default scope when config.scope is absent', () => {
		let cfg_no_scope = { client_id: 'c1', redirect_uri: 'https://app.example.com/cb' };
		let res = oidc.get_auth_url(null, cfg_no_scope, VALID_DISCOVERY, VALID_PARAMS);
		assert.match(contains({ ok: true }), res);
		assert.match(true, index(res.data, 'scope=') >= 0);
		assert.match(true, index(res.data, 'openid') >= 0);
	});

	// Any state shorter than 16 characters must be rejected — the length check is
	// the only CSRF entropy guard at this layer.
	prop('any state shorter than 16 characters is always rejected',
		gen.string({ max_len: 15 }),
		(short_state, ctx) => {
			ctx.classify('empty', length(short_state) == 0);
			assert.match(contains({ ok: false, error: 'MISSING_STATE_PARAMETER' }),
				oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY,
					{ state: short_state, nonce: NONCE, code_challenge: CHALLENGE }));
		}
	);

	prop('any nonce shorter than 16 characters is always rejected',
		gen.string({ max_len: 15 }),
		(short_nonce, ctx) => {
			ctx.classify('empty', length(short_nonce) == 0);
			assert.match(contains({ ok: false, error: 'MISSING_NONCE_PARAMETER' }),
				oidc.get_auth_url(null, VALID_CONFIG, VALID_DISCOVERY,
					{ state: STATE, nonce: short_nonce, code_challenge: CHALLENGE }));
		}
	);
});

// ─── exchange_code ───────────────────────────────────────────────────────────

const EXCHANGE_DISCOVERY = { token_endpoint: 'https://idp.example.com/token' };
// Minimum valid PKCE verifier: 43 base64url chars (RFC 7636 §4.1)
const VERIFIER_MIN  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq'; // 43 chars
const VERIFIER_MAX  = VERIFIER_MIN + VERIFIER_MIN + VERIFIER_MIN;     // 129 chars (one over the limit)

describe('oidc: exchange_code', () => {
	it('returns INSECURE_TOKEN_ENDPOINT for an http token_endpoint', () => {
		assert.match(contains({ ok: false, error: 'INSECURE_TOKEN_ENDPOINT' }),
			oidc.exchange_code(null, {}, { token_endpoint: 'http://idp.example.com/token' }, 'code', VERIFIER_MIN, null));
	});

	it('returns INVALID_PKCE_VERIFIER when verifier is shorter than 43 characters', () => {
		assert.match(contains({ ok: false, error: 'INVALID_PKCE_VERIFIER' }),
			oidc.exchange_code(LOG, {}, EXCHANGE_DISCOVERY, 'code', 'too-short', null));
	});

	it('returns INVALID_PKCE_VERIFIER when verifier is longer than 128 characters', () => {
		assert.match(contains({ ok: false, error: 'INVALID_PKCE_VERIFIER' }),
			oidc.exchange_code(LOG, {}, EXCHANGE_DISCOVERY, 'code', VERIFIER_MAX, null));
	});

	it('returns INVALID_PKCE_VERIFIER when verifier is not a string', () => {
		assert.match(contains({ ok: false, error: 'INVALID_PKCE_VERIFIER' }),
			oidc.exchange_code(LOG, {}, EXCHANGE_DISCOVERY, 'code', null, null));
	});
});

// ─── verify_id_token ─────────────────────────────────────────────────────────

describe('oidc: verify_id_token', () => {
	it('returns MISSING_ID_TOKEN when id_token is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_ID_TOKEN' }),
			oidc.verify_id_token(LOG, {}, [], {}, {}, {}, 0, null));
	});

	it('returns MISSING_ID_TOKEN when id_token is not a string', () => {
		assert.match(contains({ ok: false, error: 'MISSING_ID_TOKEN' }),
			oidc.verify_id_token(LOG, { id_token: 42 }, [], {}, {}, {}, 0, null));
	});

	it('returns UNSUPPORTED_ALGORITHM when alg is not in the policy allow-list', () => {
		let tok = jwt_with_header({ alg: 'HS256', kid: 'k1' });
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0, { allowed_algs: ['RS256', 'ES256'] }));
	});

	it('returns NO_KEYS_AVAILABLE when token has no kid and keys is empty', () => {
		let tok = jwt_with_header({ alg: 'RS256' });
		assert.match(contains({ ok: false, error: 'NO_KEYS_AVAILABLE' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0, null));
	});

	it('returns KEY_NOT_FOUND when kid does not match any provided key', () => {
		let tok = jwt_with_header({ alg: 'RS256', kid: 'unknown-kid' });
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0, null));
	});
});

// ─── discover — real flow ──────────────────────────────────────────────────────

describe('oidc: discover', () => {
	it('successful fetch & schema', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: f.MOCK_DISCOVERY } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(truthy(), res.ok);
			assert.match(f.MOCK_DISCOVERY.issuer, res.data.issuer);
		});
	});

	it('handle non-JSON response', () => {
		let issuer = "https://broken.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: "<html>Error</html>" } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(falsy(), res.ok);
			assert.match("INVALID_DISCOVERY_DOC", res.error);
		});
	});

	it('reject issuer mismatch', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

		with_context({
			http_client: { data: { [url]: { status: 200, body: evil_doc } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(falsy(), res.ok);
			assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
		});
	});

	it('reject document missing issuer field', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let bad_doc = { ...f.MOCK_DISCOVERY };
		delete bad_doc.issuer;

		with_context({
			http_client: { data: { [url]: { status: 200, body: bad_doc } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(falsy(), res.ok, "Should fail if issuer field is missing");
			assert.match("DISCOVERY_MISSING_ISSUER", res.error);
		});
	});

	it('cache robustness & TTL', () => {
		let issuer = "https://trusted.idp";
		let cache_path = "/var/run/luci-sso/oidc-cache-test.json";
		let url = issuer + "/.well-known/openid-configuration";
		let get_call_count = 0;

		with_context({
			fs: { data: {} },
			http_client: {
				behavior: {
					get: (req_url, opts) => {
						if (req_url == url) {
							get_call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			oidc.discover(deps, issuer, { cache_path, ttl: 100 });

			let before = get_call_count;
			let res = oidc.discover(deps, issuer, { cache_path, ttl: 100 });
			assert.match(truthy(), res.ok, "Should hit cache");
			assert.match(before, get_call_count, "Should not have made a network request");

			before = get_call_count;
			oidc.discover(deps, issuer, { cache_path, ttl: -1 });
			assert.match(before + 1, get_call_count, "Should have attempted network refresh");
		});
	});

	it('immutable cache (no pollution)', () => {
		let issuer = "https://public.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let mock_disc = {
			issuer: issuer,
			authorization_endpoint: issuer + "/auth",
			token_endpoint: issuer + "/token",
			jwks_uri: issuer + "/jwks"
		};

		with_context({
			http_client: { data: { [url]: { status: 200, body: mock_disc } } }
		}, (deps) => {
			let res1 = oidc.discover(deps, issuer);
			assert.match(truthy(), res1.ok);
			res1.data.token_endpoint = "http://EVIL";

			let res2 = oidc.discover(deps, issuer);
			assert.match(issuer + "/token", res2.data.token_endpoint, "Cache must not be polluted");
		});
	});

	it('handle insecure end_session_endpoint', () => {
		let disc = {
			issuer: "https://idp.com",
			authorization_endpoint: "https://idp.com/auth",
			token_endpoint: "https://idp.com/token",
			jwks_uri: "https://idp.com/jwks",
			end_session_endpoint: "http://insecure.com/logout"
		};

		with_context({
			http_client: { data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: disc } } }
		}, (deps) => {
			let res = oidc.discover(deps, "https://idp.com");
			assert.match(truthy(), res.ok);
			assert.match(falsy(), res.data.end_session_endpoint, "Insecure end_session_endpoint MUST be removed");
		});
	});

	it('reject insecure issuer URL', () => {
		with_context({}, (deps) => {
			let res = oidc.discover(deps, "http://insecure.idp");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ISSUER_URL", res.error);
		});
	});

	it('reject insecure internal issuer URL', () => {
		with_context({}, (deps) => {
			let res = oidc.discover(deps, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_FETCH_URL", res.error);
		});
	});

	it('reject discovery document with insecure endpoints', () => {
		let evil_disc = { ...f.MOCK_DISCOVERY, jwks_uri: "http://insecure.idp/jwks" };
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: evil_disc } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ENDPOINT", res.error);
		});
	});

	it('reject massive discovery response (DoS protection)', () => {
		let garbage = "1234567890";
		for (let i = 0; i < 15; i++) garbage += garbage; // 10 * 2^15 = 327,680 chars (~320KB)
		let massive_body = { ...f.MOCK_DISCOVERY, garbage };

		with_context({
			http_client: {
				data: { "https://massive.idp/.well-known/openid-configuration": { status: 200, body: massive_body } }
			}
		}, (deps) => {
			let res = oidc.discover(deps, "https://massive.idp");
			assert.match(falsy(), res.ok, "Should reject massive discovery document");
			assert.match("DISCOVERY_NETWORK_ERROR", res.error, "Should return network error (aborted read)");
		});
	});
});

// ─── exchange_code — real flow ──────────────────────────────────────────────────

describe('oidc: exchange_code — flow', () => {
	it('successful exchange', () => {
		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 200, body: { access_token: "mock-access", id_token: "mock-id" } } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code123", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
			assert.match(truthy(), res.ok);
		});
	});

	it('handle IdP errors (401/400)', () => {
		let v = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";

		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 401, body: { error: "invalid_client" } } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
			assert.match(falsy(), res.ok);
			assert.match("TOKEN_EXCHANGE_FAILED", res.error);
		});

		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "something_else" } } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
			assert.match(falsy(), res.ok);
			assert.match("TOKEN_EXCHANGE_FAILED", res.error);
		});

		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", v);
			assert.match(falsy(), res.ok);
			assert.match("OIDC_INVALID_GRANT", res.error);
		});
	});

	it('enforce PKCE verifier length', () => {
		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 200, body: { access_token: "a", id_token: "i" } } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "weak");
			assert.match(falsy(), res.ok);
			assert.match("INVALID_PKCE_VERIFIER", res.error);

			let long_verifier = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";
			let res_ok = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", long_verifier);
			assert.match(truthy(), res_ok.ok);
		});
	});

	it('handle network failure during exchange', () => {
		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { error: "TLS_VERIFY_FAILED" } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "verifier-is-long-enough-to-pass-basic-check-123");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("TOKEN_ENDPOINT_NETWORK_ERROR", res.error);
		});
	});
});

// ─── verify_id_token — claims validation ────────────────────────────────────────

describe('oidc: verify_id_token — claims', () => {
	it('support multi-audience arrays', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let time = 1516239022;

		let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], azp: f.MOCK_CONFIG.client_id, at_hash: ah };
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			assert.match(truthy(), oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY).ok);
		});

		payload.aud = [ "wrong-app-1", "wrong-app-2" ];
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("AUDIENCE_MISMATCH", res.error);
		});

		payload.aud = [];
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("INVALID_AUDIENCE", res.error);
		});
	});

	it('support AZP claim', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], at_hash: ah };
		let time = 1516239022;

		with_context({}, (deps) => {
			payload.azp = "evil-app";
			let token = h.generate_id_token(payload, PRIVKEY, "RS256");
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("AZP_MISMATCH", res.error);

			payload.azp = f.MOCK_CONFIG.client_id;
			token = h.generate_id_token(payload, PRIVKEY, "RS256");
			assert.match(truthy(), oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY).ok);

			payload.aud = f.MOCK_CONFIG.client_id;
			payload.azp = "mismatched-client";
			token = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("AZP_MISMATCH", res.error, "AZP must match even for single audience");
		});
	});

	it('reject expired ID token', () => {
		let payload = { ...f.MOCK_CLAIMS, exp: 1500 };
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		let keys = JWKS.keys;

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match("TOKEN_EXPIRED", res.error);
		});
	});

	it('enforce nonce matching', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = { ...f.MOCK_CLAIMS, at_hash: ah };
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		let time = 1516239022;

		with_context({}, (deps) => {
			let handshake_state = { nonce: "n" };
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match(truthy(), res.ok);

			handshake_state.nonce = "different-nonce";
			res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("NONCE_MISMATCH", res.error);

			delete payload.nonce;
			let token_no_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token_no_nonce, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("MISSING_NONCE", res.error);

			payload.nonce = "n";
			let token_with_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token_with_nonce, access_token: at }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("MISSING_NONCE", res.error);
		});
	});

	it('handle binary garbage', () => {
		let keys = JWKS.keys;

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: "not.a.token" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(falsy(), res.ok);

			res = oidc.verify_id_token(deps, { id_token: "\x00\xff\xdeadbeef" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(falsy(), res.ok);
		});
	});

	it('at_hash validation ensures token binding', () => {
		let access_token = "valid-access-token-123";
		let keys = JWKS.keys;
		let full_hash = crypto.hash_sha256(native, access_token).data;
		let left_half = encoding.binary_truncate(full_hash, 16).data;
		let correct_hash = encoding.b64url_encode(left_half).data;
		let time = 1516239022;

		with_context({}, (deps) => {
			let p1 = { ...f.MOCK_CLAIMS, at_hash: correct_hash };
			let res1 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match(truthy(), res1.ok, "Should accept matching at_hash");

			let p2 = { ...f.MOCK_CLAIMS };
			let res2 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p2, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("MISSING_ACCESS_TOKEN", !res2.ok && res2.error, "Should fail if access_token is missing");

			let res3 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token: "wrong" }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("AT_HASH_MISMATCH", !res3.ok && res3.error);

			let res4 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p2, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("MISSING_AT_HASH", !res4.ok && res4.error);

			let res5 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time, TEST_POLICY);
			assert.match("MISSING_ACCESS_TOKEN", !res5.ok && res5.error);
		});
	});

	it('at_hash validation byte-safety torture', () => {
		let access_token = "at-hash-torture-input-1";
		let keys = JWKS.keys;
		let full_hash = crypto.hash_sha256(native, access_token).data;
		let left_half = encoding.binary_truncate(full_hash, 16).data;
		let correct_at_hash = encoding.b64url_encode(left_half).data;

		with_context({}, (deps) => {
			let p = { ...f.MOCK_CLAIMS, at_hash: correct_at_hash };
			let res = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(truthy(), res.ok, "at_hash validation MUST be byte-safe (failed for binary sequence)");
		});
	});

	it('require azp when aud has multiple audiences', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = {
			...f.MOCK_CLAIMS,
			aud: [ f.MOCK_CONFIG.client_id, "other-service" ],
			at_hash: ah
		};
		delete payload.azp;
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(falsy(), res.ok, "Verification MUST fail when aud has multiple audiences but azp is missing");
			assert.match("MISSING_AZP_CLAIM", res.error);
		});
	});

	it('accept single-element aud array without azp', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = {
			...f.MOCK_CLAIMS,
			aud: [ f.MOCK_CONFIG.client_id ],
			at_hash: ah
		};
		delete payload.azp;
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(truthy(), res.ok, `Verification MUST succeed for single-element aud array without azp (Error: ${res.error})`);
		});
	});

	it('reject azp mismatch even for single-element aud', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = {
			...f.MOCK_CLAIMS,
			aud: [ f.MOCK_CONFIG.client_id ],
			azp: "malicious-client",
			at_hash: ah
		};
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(falsy(), res.ok, "Verification MUST fail when azp claim is present but mismatched");
			assert.match("AZP_MISMATCH", res.error);
		});
	});

	it('reject missing mandatory claims (exp, iat)', () => {
		let keys = JWKS.keys;

		let p_no_exp = { ...f.MOCK_CLAIMS, exp: null, nonce: "n1", sub: "u1", iat: 100 };
		let t_no_exp = { id_token: h.generate_id_token(p_no_exp, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_exp, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'exp' claim");
			assert.match("MISSING_EXP_CLAIM", res.error);
		});

		let p_no_iat = { ...f.MOCK_CLAIMS, iat: null, nonce: "n1", sub: "u1" };
		let t_no_iat = { id_token: h.generate_id_token(p_no_iat, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_iat, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'iat' claim");
			assert.match("MISSING_IAT_CLAIM", res.error);
		});
	});

	it('reject missing mandatory at_hash claim and log the violation (W2)', () => {
		let keys = JWKS.keys;
		let payload = { ...f.MOCK_CLAIMS, at_hash: null, nonce: "n1", sub: "u1" };
		let tokens = { id_token: h.generate_id_token(payload, PRIVKEY, "RS256"), access_token: "at123" };
		let log_calls = [];

		with_context({}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);
			let res = oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 1500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'at_hash' claim");
			assert.match("MISSING_AT_HASH", res.error);
		});

		let found = false;
		for (let e in log_calls) {
			if (e[0] == "error" && match(e[1], /ID Token missing mandatory at_hash claim/)) {
				found = true; break;
			}
		}
		assert.match(truthy(), found, "Should log security violation");
	});

	it('preserves the groups claim in user_data', () => {
		let keys = [ f.MOCK_JWK ];
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let groups = ["admin", "dev"];
		let payload = { ...f.MOCK_CLAIMS, at_hash: ah, groups: groups };
		let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(truthy(), res.ok, "Verification should succeed");
			assert.match(truthy(), res.data.groups, "Groups claim SHOULD be present in user_data");
			assert.match(groups, res.data.groups, "Groups claim SHOULD match original");
		});
	});
});

// ─── fetch_jwks — real flow ─────────────────────────────────────────────────────

describe('oidc: fetch_jwks — flow', () => {
	it('successful fetch, cache & TTL', () => {
		let jwks_uri = "https://trusted.idp/jwks";
		let cache_path = "/var/run/luci-sso/jwks-cache-test.json";
		let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
		let get_call_count = 0;

		with_context({
			fs: { data: {} },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == jwks_uri) {
							get_call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", mock_jwks) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = oidc.fetch_jwks(deps, jwks_uri, { cache_path, ttl: 3600 });
			assert.match(truthy(), res.ok);
			assert.match("k1", res.data[0].kid);

			let before = get_call_count;
			let res2 = oidc.fetch_jwks(deps, jwks_uri, { cache_path, ttl: 3600 });
			assert.match(truthy(), res2.ok, "Should hit cache");
			assert.match(before, get_call_count, "Should not have made a network request");
		});
	});

	it('handle corrupted cache', () => {
		let jwks_uri = "https://trusted.idp/jwks";
		let cache_path = "/var/run/luci-sso/jwks-corrupt.json";
		let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };

		with_context({
			fs: { data: { [cache_path]: "{ invalid json !!! }" } },
			http_client: { data: { [jwks_uri]: { status: 200, body: mock_jwks } } },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = oidc.fetch_jwks(deps, jwks_uri, { cache_path });
			assert.match(truthy(), res.ok, "Should fall back to network if cache is corrupted");
			assert.match("k1", res.data[0].kid);
		});
	});
});

// ─── parameter encoding ─────────────────────────────────────────────────────────

describe('oidc: encoding', () => {
	it('parameter torture test', () => {
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

		let res = oidc.get_auth_url(null, complex_config, f.MOCK_DISCOVERY, params);
		assert.match(truthy(), res.ok, "get_auth_url should succeed");
		let auth_url = res.data;
		assert.match(truthy(), index(auth_url, "client_id=app%20%26%20user") != -1, "client_id must be encoded");
		assert.match(truthy(), index(auth_url, "redirect_uri=https%3A%2F%2Frouter.lan%2Fcallback%3Fparam%3D1%26other%3D2") != -1, "redirect_uri must be fully encoded");
		assert.match(truthy(), index(auth_url, "state=state%20with%20spaces%20%26%20symbols%20%231_long_enough") != -1, "state must be encoded");

		let captured_body = null;
		with_context({
			http_client: {
				behavior: {
					post: (url, opts) => {
						captured_body = opts ? opts.body : null;
						return { ok: true, data: { status: 200, body: sprintf("%J", {}) } };
					}
				}
			}
		}, (deps) => {
			oidc.exchange_code(deps, complex_config, f.MOCK_DISCOVERY, "code & space", "verifier/slash-that-is-at-least-43-chars-long-!!!", "s1");
		});

		assert.match(truthy(), captured_body, "Should have made an HTTP POST call");
		assert.match(truthy(), index(captured_body, "code=code%20%26%20space") != -1, "code in body must be encoded");
		assert.match(truthy(), index(captured_body, "code_verifier=verifier%2Fslash-that-is-at-least-43-chars-long-!!!") != -1, "verifier in body must be encoded");
	});
});

// ─── fetch_userinfo ─────────────────────────────────────────────────────────────

describe('oidc: fetch_userinfo', () => {
	it('successful fetch', () => {
		let endpoint = "https://trusted.idp/userinfo";
		let at = "access-token-123";
		let mock_res = { sub: "user-123", email: "user@example.com" };

		with_context({
			http_client: { data: { [endpoint]: { status: 200, body: mock_res } } }
		}, (deps) => {
			let res = oidc.fetch_userinfo(deps, endpoint, at);
			assert.match(truthy(), res.ok);
			assert.match("user@example.com", res.data.email);
		});
	});

	it('reject missing sub claim', () => {
		let endpoint = "https://trusted.idp/userinfo";

		with_context({
			http_client: { data: { [endpoint]: { status: 200, body: { email: "no-sub@example.com" } } } }
		}, (deps) => {
			let res = oidc.fetch_userinfo(deps, endpoint, "at");
			assert.match(falsy(), res.ok);
			assert.match("MISSING_SUB_CLAIM", res.error);
		});
	});

	it('returns the sub verbatim (caller enforces binding)', () => {
		let endpoint = "https://trusted.idp/userinfo";
		let at = "access-token-123";
		let mock_res = { sub: "EVIL-USER", email: "victim@example.com" };

		with_context({
			http_client: { data: { [endpoint]: { status: 200, body: mock_res } } }
		}, (deps) => {
			let res = oidc.fetch_userinfo(deps, endpoint, at);
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match("EVIL-USER", res.data.sub);
		});
	});
});
