import { describe, it, prop, gen, assert, contains, truthy, falsy, spy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Real-flow coverage below enters at oidc's exported functions with a faked deps
// graph (with_context builds http+fs+clock+native from proxies). oidc is unit-
// classified; the handshake orchestration halves of the mixed tier2 files live in
// integration/handshake_test.uc.
const PRIVKEY      = f.MOCK_PRIVKEY;
const JWKS         = { keys: [ f.MOCK_JWK ] };

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

// ─── IdP back-channel failures: 502 to the browser, upstream status to the log ─

describe('oidc: back-channel failures map to 502 Bad Gateway', () => {
	const V = "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long";

	// Runs exchange_code against one token-endpoint reply; returns { res, logs }.
	function exchange(reply) {
		let out = { res: null, logs: [] };
		with_context({ http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: reply } } }, (deps) => {
			deps.log = (l, m) => push(out.logs, m);
			out.res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", V, "sess1");
		});
		return out;
	}

	for (let upstream in [ 400, 401, 403, 500, 502, 503 ]) {
		it(`TOKEN_EXCHANGE_FAILED is 502 for an upstream ${upstream}, which is logged once`, () => {
			let r = exchange({ status: upstream, body: { error: "invalid_client" } });
			assert.match(contains({ ok: false, error: 'TOKEN_EXCHANGE_FAILED' }), r.res);
			assert.match({ http_status: 502, upstream_status: upstream, oauth_error: "invalid_client" }, r.res.details);
			assert.match([ `Token exchange HTTP ${upstream} [session_id: sess1]` ],
				filter(r.logs, (m) => index(m, `${upstream}`) >= 0));
		});
	}

	it('OIDC_INVALID_GRANT is 502, and the upstream status is logged', () => {
		let r = exchange({ status: 400, body: { error: "invalid_grant" } });
		assert.match(contains({ ok: false, error: 'OIDC_INVALID_GRANT' }), r.res);
		assert.match({ http_status: 502, upstream_status: 400, oauth_error: "invalid_grant" }, r.res.details);
		assert.match(1, length(filter(r.logs, (m) => m == "Token exchange failed (invalid_grant, HTTP 400) [session_id: sess1]")), sprintf("%J", r.logs));
	});

	it('TOKEN_ENDPOINT_NETWORK_ERROR is 502', () => {
		let r = exchange({ error: "CONNECTION_FAILED" });
		assert.match(contains({ ok: false, error: 'TOKEN_ENDPOINT_NETWORK_ERROR' }), r.res);
		assert.match({ http_status: 502, cause: "HTTP_REQUEST_FAILED (CONNECTION_FAILED)" }, r.res.details);
	});

	it('the OAuth error code is kept only when it is a short code, never free text', () => {
		for (let body in [ {}, "not json", [ "invalid_client" ], { error: 42 }, { error: "" },
		                   { error: "invalid client <script>" }, { error: "x\nforged" }, { error: "a" + sprintf("%064d", 0) } ]) {
			let r = exchange({ status: 400, body });
			assert.match(contains({ error: 'TOKEN_EXCHANGE_FAILED' }), r.res, sprintf("%J", body));
			assert.match(null, r.res.details.oauth_error, sprintf("%J", body));
			assert.match(400, r.res.details.upstream_status);
		}
		assert.match("unauthorized_client", exchange({ status: 400, body: { error: "unauthorized_client" } }).res.details.oauth_error);
	});

	it('sends client_id and client_secret in the form body (client_secret_post)', () => {
		let sent;
		with_context({ http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } } } } }, (deps) => {
			oidc.exchange_code(deps, { ...f.MOCK_CONFIG, redirect_uri: "https://r/cb" }, f.MOCK_DISCOVERY, "c 1", V, null);
			sent = spy(deps.http).calls.post[0];
		});
		assert.match(f.MOCK_DISCOVERY.token_endpoint, sent[0]);
		assert.match({ "Content-Type": "application/x-www-form-urlencoded" }, sent[1].headers);
		assert.match(`grant_type=authorization_code&client_id=luci-app&client_secret=top-secret&redirect_uri=https%3A%2F%2Fr%2Fcb&code=c%201&code_verifier=${V}`, sent[1].body);
	});

	it('TOKEN_RESPONSE_INVALID_JSON is 502', () => {
		let r = exchange({ status: 200, body: "not json" });
		assert.match(contains({ ok: false, error: 'TOKEN_RESPONSE_INVALID_JSON' }), r.res);
		assert.match({ http_status: 502 }, r.res.details);
	});

	it('USERINFO_FETCH_FAILED is 502, and the upstream status is logged', () => {
		let endpoint = "https://trusted.idp/userinfo";
		let res, logs = [];
		with_context({ http_client: { data: { [endpoint]: { status: 401, body: {} } } } }, (deps) => {
			deps.log = (l, m) => push(logs, m);
			res = oidc.fetch_userinfo(deps, endpoint, "at", "user-123");
		});
		assert.match(contains({ ok: false, error: 'USERINFO_FETCH_FAILED' }), res);
		assert.match({ http_status: 502 }, res.details);
		assert.match(1, length(filter(logs, (m) => m == "UserInfo fetch HTTP 401")), sprintf("%J", logs));
	});

	it('a local fault before the call carries no gateway status', () => {
		with_context({ http_client: { data: {} } }, (deps) => {
			let r = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "short");
			assert.match(contains({ ok: false, error: 'INVALID_PKCE_VERIFIER' }), r);
			assert.match(null, r.details);
		});
	});
});

// ─── verify_id_token ─────────────────────────────────────────────────────────

describe('oidc: verify_id_token', () => {
	it('returns MISSING_ID_TOKEN when id_token is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_ID_TOKEN' }),
			oidc.verify_id_token(LOG, {}, [], {}, {}, {}, 0));
	});

	it('returns MISSING_ID_TOKEN when id_token is not a string', () => {
		assert.match(contains({ ok: false, error: 'MISSING_ID_TOKEN' }),
			oidc.verify_id_token(LOG, { id_token: 42 }, [], {}, {}, {}, 0));
	});

	it('returns UNSUPPORTED_ALGORITHM when alg is not in the allow-list', () => {
		let tok = jwt_with_header({ alg: 'HS256', kid: 'k1' });
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0));
	});

	it('returns NO_KEYS_AVAILABLE when token has no kid and keys is empty', () => {
		let tok = jwt_with_header({ alg: 'RS256' });
		assert.match(contains({ ok: false, error: 'NO_KEYS_AVAILABLE' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0));
	});

	it('returns KEY_NOT_FOUND when kid does not match any provided key', () => {
		let tok = jwt_with_header({ alg: 'RS256', kid: 'unknown-kid' });
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			oidc.verify_id_token(LOG, { id_token: tok }, [], {}, {}, {}, 0));
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
	it('rejects an aud array with an additional untrusted audience, even with azp = client_id (OIDC Core §3.1.3.7 (3))', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let time = 1516239022;

		let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id, "other" ], azp: f.MOCK_CONFIG.client_id, at_hash: ah };
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match(contains({ ok: false, error: "AUDIENCE_MISMATCH" }), res);
		});

		payload.aud = [ f.MOCK_CONFIG.client_id, 42 ];
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("MALFORMED_AUDIENCE", res.error, "a later non-string entry is still type-checked");
		});

		payload.aud = [ "wrong-app-1", "wrong-app-2" ];
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("AUDIENCE_MISMATCH", res.error);
		});

		payload.aud = [];
		token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("INVALID_AUDIENCE", res.error);
		});
	});

	it('support AZP claim', () => {
		let keys = JWKS.keys;
		let at = "mock-at";
		let full_hash = crypto.hash_sha256(native, at).data;
		let ah = encoding.b64url_encode(substr(full_hash, 0, 16)).data;
		let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id ], at_hash: ah };
		let time = 1516239022;

		with_context({}, (deps) => {
			payload.azp = "evil-app";
			let token = h.generate_id_token(payload, PRIVKEY, "RS256");
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("AZP_MISMATCH", res.error);

			payload.azp = f.MOCK_CONFIG.client_id;
			token = h.generate_id_token(payload, PRIVKEY, "RS256");
			assert.match(truthy(), oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time).ok);

			payload.aud = f.MOCK_CONFIG.client_id;
			payload.azp = "mismatched-client";
			token = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("AZP_MISMATCH", res.error, "AZP must match even for single audience");
		});
	});

	it('reject expired ID token', () => {
		let payload = { ...f.MOCK_CLAIMS, exp: 1500 };
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		let keys = JWKS.keys;

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
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
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time);
			assert.match(truthy(), res.ok);

			handshake_state.nonce = "different-nonce";
			res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time);
			assert.match("NONCE_MISMATCH", res.error);

			delete payload.nonce;
			let token_no_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token_no_nonce, access_token: at }, keys, f.MOCK_CONFIG, handshake_state, f.MOCK_DISCOVERY, time);
			assert.match("MISSING_NONCE", res.error);

			payload.nonce = "n";
			let token_with_nonce = h.generate_id_token(payload, PRIVKEY, "RS256");
			res = oidc.verify_id_token(deps, { id_token: token_with_nonce, access_token: at }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, time);
			assert.match("MISSING_NONCE", res.error);
		});
	});

	it('handle binary garbage', () => {
		let keys = JWKS.keys;

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: "not.a.token" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, 1516239022);
			assert.match(falsy(), res.ok);

			res = oidc.verify_id_token(deps, { id_token: "\x00\xff\xdeadbeef" }, keys, f.MOCK_CONFIG, {}, f.MOCK_DISCOVERY, 1516239022);
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
			let res1 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match(truthy(), res1.ok, "Should accept matching at_hash");

			let p2 = { ...f.MOCK_CLAIMS };
			let res2 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p2, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("MISSING_ACCESS_TOKEN", !res2.ok && res2.error, "Should fail if access_token is missing");

			let res3 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256"), access_token: "wrong" }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match("AT_HASH_MISMATCH", !res3.ok && res3.error);

			let res4 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p2, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
			assert.match(truthy(), res4.ok, "Should accept an ID token without at_hash (optional in the code flow)");

			let res5 = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p1, PRIVKEY, "RS256") }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, time);
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
			let res = oidc.verify_id_token(deps, { id_token: h.generate_id_token(p, PRIVKEY, "RS256"), access_token }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
			assert.match(truthy(), res.ok, "at_hash validation MUST be byte-safe (failed for binary sequence)");
		});
	});

	it('rejects azp that is present but not the client_id string: "", a number, null (OIDC Core §3.1.3.7 (5))', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		with_context({}, (deps) => {
			for (let azp in [ "", 123, 0, false, null, [ f.MOCK_CONFIG.client_id ] ]) {
				let token = h.generate_id_token({ ...f.MOCK_CLAIMS, aud: f.MOCK_CONFIG.client_id, azp, at_hash: ah }, PRIVKEY, "RS256");
				let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
				assert.match(contains({ ok: false, error: "AZP_MISMATCH" }), res, sprintf("azp %J", azp));
			}
		});
	});

	it('accepts the Pocket ID shape: aud ["<client_id>"] and no azp (issue #1)', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let payload = { ...f.MOCK_CLAIMS, aud: [ f.MOCK_CONFIG.client_id ], at_hash: ah };
		delete payload.azp;
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
			assert.match(contains({ ok: true, data: contains({ sub: f.MOCK_CLAIMS.sub }) }), res, `${res.error}`);
		});
	});

	it('accepts the Keycloak/Authentik shape: aud "<client_id>", with or without azp = client_id', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		with_context({}, (deps) => {
			for (let with_azp in [ true, false ]) {
				let payload = { ...f.MOCK_CLAIMS, aud: f.MOCK_CONFIG.client_id, at_hash: ah };
				if (with_azp) payload.azp = f.MOCK_CONFIG.client_id; else delete payload.azp;
				let token = h.generate_id_token(payload, PRIVKEY, "RS256");
				let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
				assert.match(contains({ ok: true }), res, `azp ${with_azp}: ${res.error}`);
			}
		});
	});

	it('requires sub to be a non-empty string (OIDC Core §2)', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		with_context({}, (deps) => {
			for (let sub in [ null, "", 123, 0, true, [ "u" ], { id: "u" } ]) {
				let payload = { ...f.MOCK_CLAIMS, sub, at_hash: ah };
				if (sub == null) delete payload.sub;
				let token = h.generate_id_token(payload, PRIVKEY, "RS256");
				let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
				assert.match(contains({ ok: false, error: "MISSING_SUB_CLAIM" }), res, sprintf("sub %J", sub));
			}
		});
	});

	it('checks iss against the discovered issuer exactly (OIDC Core §3.1.3.7 (2))', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		// An Authentik-style issuer with a trailing slash, configured exactly.
		let issuer = "https://trusted.idp/application/o/luci/";
		let config = { ...f.MOCK_CONFIG, issuer_url: issuer };
		let disc = { ...f.MOCK_DISCOVERY, issuer };
		with_context({}, (deps) => {
			let verify = (iss) => oidc.verify_id_token(deps,
				{ id_token: h.generate_id_token({ ...f.MOCK_CLAIMS, iss, at_hash: ah }, PRIVKEY, "RS256"), access_token: at },
				JWKS.keys, config, { nonce: "n" }, disc, 1516239022);
			assert.match(contains({ ok: true }), verify(issuer));
			for (let iss in [ "https://trusted.idp/application/o/luci", "HTTPS://TRUSTED.IDP/application/o/luci/", "https://trusted.idp:443/application/o/luci/" ])
				assert.match(contains({ ok: false, error: "ISSUER_MISMATCH" }), verify(iss), iss);
		});
	});

	it('returns DISCOVERY_ISSUER_MISMATCH when the discovered issuer differs from issuer_url only by normalization', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let token = h.generate_id_token({ ...f.MOCK_CLAIMS, at_hash: ah }, PRIVKEY, "RS256");
		with_context({}, (deps) => {
			for (let declared in [ f.MOCK_CONFIG.issuer_url + "/", "https://TRUSTED.idp", "https://trusted.idp:443" ]) {
				let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n" }, { ...f.MOCK_DISCOVERY, issuer: declared }, 1516239022);
				assert.match(contains({ ok: false, error: "DISCOVERY_ISSUER_MISMATCH" }), res, declared);
			}
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
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
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
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
			assert.match(falsy(), res.ok, "Verification MUST fail when azp claim is present but mismatched");
			assert.match("AZP_MISMATCH", res.error);
		});
	});

	it('reject missing mandatory claims (exp, iat)', () => {
		let keys = JWKS.keys;

		let p_no_exp = { ...f.MOCK_CLAIMS, exp: null, nonce: "n1", sub: "u1", iat: 100 };
		let t_no_exp = { id_token: h.generate_id_token(p_no_exp, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_exp, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'exp' claim");
			assert.match("MISSING_EXP_CLAIM", res.error);
		});

		let p_no_iat = { ...f.MOCK_CLAIMS, iat: null, nonce: "n1", sub: "u1" };
		let t_no_iat = { id_token: h.generate_id_token(p_no_iat, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_iat, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'iat' claim");
			assert.match("MISSING_IAT_CLAIM", res.error);
		});
	});

	it('accepts an ID token without at_hash: OPTIONAL in the code flow (OIDC Core §3.1.3.6)', () => {
		let keys = JWKS.keys;
		let payload = { ...f.MOCK_CLAIMS, nonce: "n1", sub: "u1" };
		let tokens = { id_token: h.generate_id_token(payload, PRIVKEY, "RS256"), access_token: "at123" };
		let log_calls = [];

		with_context({}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);
			let res = oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 1500);
			assert.match(contains({ ok: true, data: contains({ sub: "u1" }) }), res);
		});
		assert.match([], filter(log_calls, (e) => e[0] == "error" || e[0] == "warn"), "nothing to warn about");
	});

	it('still checks everything else when at_hash is absent', () => {
		let keys = JWKS.keys;
		let token = (claims) => h.generate_id_token({ ...f.MOCK_CLAIMS, ...claims }, PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let verify = (id_token, handshake, access_token) =>
				oidc.verify_id_token(deps, { id_token, access_token: access_token ?? "at123" }, keys, f.MOCK_CONFIG, handshake, f.MOCK_DISCOVERY, 1500);
			assert.match("NONCE_MISMATCH", verify(token({ nonce: "other" }), { nonce: "n" }).error);
			assert.match("MISSING_NONCE", verify(token({ nonce: null }), { nonce: "n" }).error);
			assert.match("AZP_MISMATCH", verify(token({ azp: "evil" }), { nonce: "n" }).error);
			assert.match("ISSUER_MISMATCH", verify(token({ iss: "https://evil.idp" }), { nonce: "n" }).error);
			assert.match("AUDIENCE_MISMATCH", verify(token({ aud: "other-client" }), { nonce: "n" }).error);
			assert.match("MISSING_ACCESS_TOKEN", oidc.verify_id_token(deps, { id_token: token({}) }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1500).error);
			let tampered = split(token({}), ".");
			tampered[1] = encoding.b64url_encode(sprintf("%J", { ...f.MOCK_CLAIMS, sub: "someone-else" })).data;
			assert.match("INVALID_SIGNATURE", verify(join(".", tampered), { nonce: "n" }).error);
		});
	});

	it('returns AT_HASH_MISMATCH for any present at_hash that does not match the access token', () => {
		let keys = JWKS.keys;
		let at = "at123";
		let right = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let other = encoding.b64url_encode(substr(crypto.hash_sha256(native, "another-token").data, 0, 16)).data;
		let flipped = ((substr(right, 0, 1) == "A") ? "B" : "A") + substr(right, 1);
		let full = encoding.b64url_encode(crypto.hash_sha256(native, at).data).data;

		with_context({}, (deps) => {
			for (let bad in [ other, flipped, full, substr(right, 0, 21), "", 0, false, [ right ], { v: right } ]) {
				let tokens = { id_token: h.generate_id_token({ ...f.MOCK_CLAIMS, at_hash: bad }, PRIVKEY, "RS256"), access_token: at };
				let res = oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1500);
				assert.match(contains({ ok: false, error: "AT_HASH_MISMATCH" }), res, sprintf("at_hash %J", bad));
			}
			let tokens = { id_token: h.generate_id_token({ ...f.MOCK_CLAIMS, at_hash: right }, PRIVKEY, "RS256"), access_token: at };
			assert.match(truthy(), oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1500).ok, "the right one passes");
		});
	});

	it('preserves the groups claim in user_data', () => {
		let keys = [ f.MOCK_JWK ];
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let groups = ["admin", "dev"];
		let payload = { ...f.MOCK_CLAIMS, at_hash: ah, groups: groups };
		let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
			assert.match(truthy(), res.ok, "Verification should succeed");
			assert.match(truthy(), res.data.groups, "Groups claim SHOULD be present in user_data");
			assert.match(groups, res.data.groups, "Groups claim SHOULD match original");
		});
	});

	it('passes the email_verified claim to user_data as sent, or null when absent', () => {
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		for (let v in [ true, false, "true", null ]) {
			let payload = { ...f.MOCK_CLAIMS, at_hash: ah, email: "a@b.c", email_verified: v };
			if (v == null) delete payload.email_verified;
			let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
			with_context({}, (deps) => {
				let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, [ f.MOCK_JWK ], f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022);
				assert.match(contains({ ok: true, data: contains({ email: "a@b.c" }) }), res, `${v}`);
				assert.match(v, res.data.email_verified, `${v}`);
			});
		}
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
	let endpoint = "https://trusted.idp/userinfo";

	// Calls fetch_userinfo against a UserInfo endpoint answering 200 with body.
	let fetch = (body, expected_sub) => {
		let res;
		with_context({
			http_client: { data: { [endpoint]: { status: 200, body } } }
		}, (deps) => {
			res = oidc.fetch_userinfo(deps, endpoint, "access-token-123", expected_sub);
		});
		return res;
	};

	it('returns the claims when the sub is exactly the expected sub', () => {
		let res = fetch({ sub: "user-123", email: "user@example.com" }, "user-123");
		assert.match(contains({ ok: true }), res);
		assert.match("user-123", res.data.sub);
		assert.match("user@example.com", res.data.email);
	});

	it('refuses a missing, non-string, empty or different sub with IDENTITY_MISMATCH (403, OIDC Core §5.3.2)', () => {
		let bodies = [
			{ email: "x@example.com" },
			{ sub: null, email: "x@example.com" },
			{ sub: 123, email: "x@example.com" },
			{ sub: true, email: "x@example.com" },
			{ sub: [ "user-123" ], email: "x@example.com" },
			{ sub: "", email: "x@example.com" },
			{ sub: "USER-123", email: "x@example.com" },
			{ sub: "user-123 ", email: "x@example.com" },
			{ sub: "EVIL-USER", email: "victim@example.com" }
		];
		for (let body in bodies) {
			let res = fetch(body, "user-123");
			assert.match(contains({ ok: false, error: "IDENTITY_MISMATCH" }), res, sprintf("body %J", body));
			assert.match({ http_status: 403 }, res.details, sprintf("body %J", body));
		}
	});

	it('refuses a JSON response that is not an object with IDENTITY_MISMATCH', () => {
		for (let body in [ [ "user-123" ], 123, "user-123" ]) {
			let res = fetch(sprintf("%J", body), "user-123");
			assert.match(contains({ ok: false, error: "IDENTITY_MISMATCH" }), res, sprintf("body %J", body));
		}
	});

	it('a sub matches only itself, byte for byte', () => {
		// Every pair of subs, including case variants of each other.
		let subs = [ "a", "A", "user-123", "User-123", "0", "x@example.com", "X@example.com" ];
		for (let expected in subs) {
			for (let got in subs) {
				let res = fetch({ sub: got, email: "x@example.com" }, expected);
				assert.match(got === expected, res.ok, sprintf("expected %J, got %J", expected, got));
			}
		}
	});

	it('dies with CONTRACT_VIOLATION when the expected sub is not a non-empty string', () => {
		for (let expected in [ null, "", 123 ])
			assert.throws(() => fetch({ sub: "", email: "x@example.com" }, expected), /CONTRACT_VIOLATION/);
	});
});

// ─── back-channel failure causes reach the log ────────────────────────────────

describe('oidc: HTTP failure causes are logged', () => {
	it('exchange_code logs the transport cause', () => {
		let logs = [];
		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { error: "CERT_NAME_MISMATCH" } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
			assert.match(contains({ ok: false, error: 'TOKEN_ENDPOINT_NETWORK_ERROR' }), res);
		});
		assert.match(1, length(filter(logs, (m) => index(m, "Token exchange network error") == 0 && index(m, ": HTTP_REQUEST_FAILED (CERT_NAME_MISMATCH)") > 0)));
	});

	it('fetch_userinfo logs the transport cause', () => {
		let logs = [];
		let endpoint = "https://trusted.idp/userinfo";
		with_context({
			http_client: { data: { [endpoint]: { error: "CONNECTION_FAILED" } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			assert.match(contains({ ok: false, error: 'USERINFO_NETWORK_ERROR' }), oidc.fetch_userinfo(deps, endpoint, "at", "user-123"));
		});
		assert.match(1, length(filter(logs, (m) => m == "UserInfo fetch network error: HTTP_REQUEST_FAILED (CONNECTION_FAILED)")));
	});
});
