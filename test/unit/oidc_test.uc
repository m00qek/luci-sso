import { describe, it, prop, gen, assert, contains } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as encoding from 'luci_sso.encoding';

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
