import { describe, it, prop, gen, assert, contains, mock } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as native from 'luci_sso.native';

// ─── fixtures ────────────────────────────────────────────────────────────────

const NOW        = 1700000000;
const CLIENT_ID  = 'client-123';
const ISSUER     = 'https://idp.example.com';
const AUTH_EP    = 'https://idp.example.com/authorize';
const TOKEN_EP   = 'https://idp.example.com/token';
const JWKS_URI   = 'https://idp.example.com/jwks';
const USERINFO   = 'https://idp.example.com/userinfo';
const REDIRECT   = 'https://router.example.com/callback';

const POLICY = { allowed_algs: ['RS256'] };

const CONFIG = {
	client_id:           CLIENT_ID,
	client_secret:       'top-secret',
	issuer_url:          ISSUER,
	internal_issuer_url: ISSUER,
	redirect_uri:        REDIRECT,
	scope:               'openid profile email',
	clock_tolerance:     60,
	roles: [
		{ name: 'ops', emails: ['user@example.com'], groups: ['ops-team'],
		  read: ['luci-app-status'], write: ['luci-app-status'] },
	],
};

const DISCOVERY_DOC = {
	issuer:                 ISSUER,
	authorization_endpoint: AUTH_EP,
	token_endpoint:         TOKEN_EP,
	jwks_uri:               JWKS_URI,
	userinfo_endpoint:      USERINFO,
};

const JWKS_OK = { keys: [{ kid: 'k1', kty: 'RSA', n: 'AQAB', e: 'AQAB' }] };

// ─── helpers ─────────────────────────────────────────────────────────────────

// The compiled `native` crypto module cannot be proxied in unit tests, so real
// crypto is used by default. This builds a native object that passes through to
// the real extension but lets a test override individual primitives (e.g. force
// signature verification to pass/fail) — mirroring how the session tests thread
// the real `native` module through `deps`.
function hybrid_native(overrides) {
	let h = {
		random:             native.random,
		sha256:             native.sha256,
		hmac_sha256:        native.hmac_sha256,
		verify_rs256:       native.verify_rs256,
		verify_es256:       native.verify_es256,
		jwk_rsa_to_pem:     native.jwk_rsa_to_pem,
		jwk_ec_p256_to_pem: native.jwk_ec_p256_to_pem,
	};
	for (let k, v in (overrides || {})) h[k] = v;
	return h;
}

// Native overrides that accept any RSA signature and PEM conversion.
const VERIFY_OK = { verify_rs256: () => true,  jwk_rsa_to_pem: () => '-----PEM-----' };
// Native overrides that reject every RSA signature (drives key-rotation retry).
const VERIFY_NO = { verify_rs256: () => false, jwk_rsa_to_pem: () => '-----PEM-----' };

// Wraps an object (or raw string) as a successful HTTP Result {status, body}.
function resp(status, body) {
	return Result.ok({ status: status, body: (type(body) == 'string') ? body : sprintf('%J', body) });
}

// A fake HTTP client that dispatches by endpoint. Routes may be Results or
// zero-arg functions returning Results (for call-counting). Missing routes
// resolve to a NO_ROUTE error so misconfigured tests fail loudly but safely.
function make_http(routes) {
	let pick = (r) => (r == null) ? Result.err('NO_ROUTE') : ((type(r) == 'function') ? r() : r);
	return {
		get: (url, opts) => {
			if (index(url, 'openid-configuration') >= 0) return pick(routes.discovery);
			if (index(url, '/jwks') >= 0)                return pick(routes.jwks);
			if (index(url, '/userinfo') >= 0)            return pick(routes.userinfo);
			return Result.err('NO_ROUTE');
		},
		post: (url, opts) => {
			if (index(url, '/token') >= 0) return pick(routes.token);
			return Result.err('NO_ROUTE');
		},
	};
}

// A fake ubus wrapper. session:create returns a fixed SID unless overridden.
function make_ubus(create_res) {
	return {
		call: (obj, method, args) => {
			if (method == 'create') return create_res || Result.ok({ ubus_rpc_session: 'SID-TEST' });
			return Result.ok({});
		},
	};
}

function make_deps(fs, native_obj, routes, ubus_create_res) {
	return {
		fs:     fs,
		native: native_obj,
		clock:  { time: () => NOW, sleep: () => null },
		log:    () => null,
		http:   make_http(routes),
		ubus:   make_ubus(ubus_create_res),
	};
}

// Persists a real handshake state so verify_state() can consume it.
function seed_handshake(deps) {
	return session.create_state(deps).data; // { token, state, nonce, code_challenge }
}

// OIDC-correct at_hash: base64url(left-half of SHA-256(access_token)).
function at_hash(access_token) {
	let h = crypto.hash_sha256(native, access_token);
	let t = encoding.binary_truncate(h.data, 16);
	return encoding.b64url_encode(t.data).data;
}

// Builds a compact JWT with the given header alg/kid and payload. The signature
// segment is a non-empty placeholder; native.verify_rs256 gates acceptance.
function jwt(alg, kid, payload) {
	let h = encoding.b64url_encode(sprintf('%J', { alg: alg, kid: kid })).data;
	let p = encoding.b64url_encode(sprintf('%J', payload)).data;
	return `${h}.${p}.AAAA`;
}

// ─── initiate ────────────────────────────────────────────────────────────────

describe('handshake: initiate', () => {
	it('returns OIDC_DISCOVERY_FAILED (500) when discovery fails', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, hybrid_native(), routes);
			routes.discovery = resp(500, {});
			let res = handshake.initiate(deps, CONFIG);
			assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
			assert.match(500, res.details.http_status);
		});
	});

	it('returns SYSTEM_INIT_FAILED (500) when the secret key is unavailable', () => {
		// Lock is held by "another process" and the key never appears → get_secret_key fails.
		mock.inject_all({ fs: { behavior: { readfile: () => null, mkdir: () => false } } }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, hybrid_native(), routes);
			routes.discovery = resp(200, DISCOVERY_DOC);
			let res = handshake.initiate(deps, CONFIG);
			assert.match(contains({ ok: false, error: 'SYSTEM_INIT_FAILED' }), res);
			assert.match(500, res.details.http_status);
		});
	});

	it('propagates STATE_SAVE_FAILED when handshake state cannot be persisted', () => {
		// Key generation succeeds, but the handshake write cannot be renamed into place.
		mock.inject_all({ fs: { behavior: { rename: (from, to) => index(from, 'handshake_') < 0 } } }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, hybrid_native(), routes);
			routes.discovery = resp(200, DISCOVERY_DOC);
			let res = handshake.initiate(deps, CONFIG);
			assert.match(contains({ ok: false, error: 'STATE_SAVE_FAILED' }), res);
		});
	});

	it('returns an auth URL and opaque token on success', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, hybrid_native(), routes);
			routes.discovery = resp(200, DISCOVERY_DOC);
			let res = handshake.initiate(deps, CONFIG);
			assert.match(contains({ ok: true }), res);
			assert.match(0, index(res.data.url, AUTH_EP));
			assert.match(true, index(res.data.url, 'state=') >= 0);
			assert.match(true, index(res.data.url, 'nonce=') >= 0);
			assert.match(true, index(res.data.url, 'code_challenge=') >= 0);
			assert.match(true, index(res.data.url, 'code_challenge_method=S256') >= 0);
			assert.match(true, length(res.data.token) > 0);
		});
	});

	prop('returns OIDC_DISCOVERY_FAILED for any non-HTTPS issuer_url',
		gen.string({ max_len: 30 }),
		(host, ctx) => {
			let cfg = { ...CONFIG, issuer_url: `http://${host}`, internal_issuer_url: `http://${host}` };
			let deps = make_deps({}, hybrid_native(), {});
			assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), handshake.initiate(deps, cfg));
		}
	);
});

// ─── authenticate: request validation ────────────────────────────────────────

describe('handshake: authenticate — request validation', () => {
	it('returns IDP_ERROR (400) when the IdP reports an error', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let deps = make_deps(injected.fs, hybrid_native(), {});
			let request = { query: { error: 'access_denied' }, cookies: {} };
			let res = handshake.authenticate(deps, CONFIG, request, POLICY);
			assert.match(contains({ ok: false, error: 'IDP_ERROR' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_CODE (400) when the authorization code is absent', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let deps = make_deps(injected.fs, hybrid_native(), {});
			let request = { query: {}, cookies: { '__Host-luci_sso_state': 'handle' } };
			let res = handshake.authenticate(deps, CONFIG, request, POLICY);
			assert.match(contains({ ok: false, error: 'MISSING_CODE' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_HANDSHAKE_COOKIE (401) when the state cookie is absent', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let deps = make_deps(injected.fs, hybrid_native(), {});
			let request = { query: { code: 'authcode' }, cookies: {} };
			let res = handshake.authenticate(deps, CONFIG, request, POLICY);
			assert.match(contains({ ok: false, error: 'MISSING_HANDSHAKE_COOKIE' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('returns STATE_NOT_FOUND (401) when the handshake handle does not exist', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let deps = make_deps(injected.fs, hybrid_native(), {});
			let request = { query: { code: 'authcode', state: 'whatever' }, cookies: { '__Host-luci_sso_state': 'ghosthandle' } };
			let res = handshake.authenticate(deps, CONFIG, request, POLICY);
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('returns STATE_PARAMETER_MISMATCH (403) when the query state does not match', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			let deps = make_deps(injected.fs, hybrid_native(), {});
			let hs = seed_handshake(deps);
			let request = { query: { code: 'authcode', state: 'WRONG-STATE' }, cookies: { '__Host-luci_sso_state': hs.token } };
			let res = handshake.authenticate(deps, CONFIG, request, POLICY);
			assert.match(contains({ ok: false, error: 'STATE_PARAMETER_MISMATCH' }), res);
			assert.match(403, res.details.http_status);
		});
	});

	prop('never throws and always returns a failed Result for an unknown handle',
		gen.string({ max_len: 40 }),
		(code, ctx) => {
			ctx.classify('empty code', length(code) == 0);
			mock.inject_all({ fs: {} }, (injected) => {
				let deps = make_deps(injected.fs, hybrid_native(), {});
				let request = { query: { code: code, state: 'x' }, cookies: { '__Host-luci_sso_state': 'ghosthandle' } };
				assert.match(contains({ ok: false }), handshake.authenticate(deps, CONFIG, request, POLICY));
			});
		}
	);
});

// ─── authenticate: OAuth flow failures ───────────────────────────────────────

describe('handshake: authenticate — OAuth flow failures', () => {
	function run(routes_setup, native_obj) {
		let out;
		mock.inject_all({ fs: {} }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, native_obj || hybrid_native(), routes);
			let hs = seed_handshake(deps);
			routes_setup(routes, hs);
			let request = { query: { code: 'authcode', state: hs.state }, cookies: { '__Host-luci_sso_state': hs.token } };
			out = handshake.authenticate(deps, CONFIG, request, POLICY);
		});
		return out;
	}

	it('returns OIDC_DISCOVERY_FAILED (500) when discovery fails in the callback', () => {
		let res = run((routes) => { routes.discovery = resp(503, {}); });
		assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
		assert.match(500, res.details.http_status);
	});

	it('propagates TOKEN_EXCHANGE_FAILED when the token endpoint errors', () => {
		let res = run((routes) => {
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(500, {});
		});
		assert.match(contains({ ok: false, error: 'TOKEN_EXCHANGE_FAILED' }), res);
	});

	it('propagates OIDC_INVALID_GRANT (400) on an invalid_grant token response', () => {
		let res = run((routes) => {
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(400, { error: 'invalid_grant' });
		});
		assert.match(contains({ ok: false, error: 'OIDC_INVALID_GRANT' }), res);
		assert.match(400, res.details.http_status);
	});

	it('returns JWKS_FETCH_FAILED (500) when the JWKS endpoint errors', () => {
		let res = run((routes) => {
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(200, { id_token: 'a.b.c', access_token: 'at' });
			routes.jwks      = resp(500, {});
		});
		assert.match(contains({ ok: false, error: 'JWKS_FETCH_FAILED' }), res);
		assert.match(500, res.details.http_status);
	});

	it('returns ID_TOKEN_VERIFICATION_FAILED (401) with details on a malformed ID token', () => {
		let res = run((routes) => {
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(200, { id_token: 'not.a.jwt', access_token: 'at' });
			routes.jwks      = resp(200, JWKS_OK);
		});
		assert.match(contains({ ok: false, error: 'ID_TOKEN_VERIFICATION_FAILED' }), res);
		assert.match(401, res.details.http_status);
		assert.match(true, res.details.details != null);
	});

	it('forces a single JWKS refresh on INVALID_SIGNATURE with a kid, then fails', () => {
		let jwks_calls = 0;
		let res = run((routes, hs) => {
			let id_token = jwt('RS256', 'k1', {
				sub: 'user-1', iss: ISSUER, aud: CLIENT_ID, exp: NOW + 3600, iat: NOW,
				nonce: hs.nonce, at_hash: at_hash('at'),
			});
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(200, { id_token: id_token, access_token: 'at' });
			routes.jwks      = () => { jwks_calls++; return resp(200, JWKS_OK); };
		}, hybrid_native(VERIFY_NO));
		assert.match(contains({ ok: false, error: 'ID_TOKEN_VERIFICATION_FAILED' }), res);
		assert.match(2, jwks_calls);
	});
});

// ─── authenticate: post-verification behavior ────────────────────────────────

describe('handshake: authenticate — post-verification', () => {
	// Runs a full callback where the ID token verifies successfully. `claims`
	// extends the default verified payload; `access_token`, `userinfo`, `fs` and
	// `ubus_create_res` steer the individual post-verification branches.
	function run_verified(opts) {
		let out;
		let access_token = opts.access_token || 'opaque-access-token';
		mock.inject_all({ fs: opts.fs || {} }, (injected) => {
			let routes = {};
			let deps = make_deps(injected.fs, hybrid_native(VERIFY_OK), routes, opts.ubus_create_res);
			let hs = seed_handshake(deps);

			let payload = {
				sub: 'user-1', iss: ISSUER, aud: CLIENT_ID, exp: NOW + 3600, iat: NOW,
				nonce: hs.nonce, at_hash: at_hash(access_token),
			};
			for (let k, v in (opts.claims || {})) payload[k] = v;

			let id_token = jwt('RS256', 'k1', payload);
			routes.discovery = resp(200, DISCOVERY_DOC);
			routes.token     = resp(200, { id_token: id_token, access_token: access_token, refresh_token: 'rt' });
			routes.jwks      = resp(200, JWKS_OK);
			if (opts.userinfo) routes.userinfo = opts.userinfo;

			let request = { query: { code: 'authcode', state: hs.state }, cookies: { '__Host-luci_sso_state': hs.token } };
			out = handshake.authenticate(deps, CONFIG, request, POLICY);
		});
		return out;
	}

	it('creates a session on the full happy path', () => {
		let res = run_verified({ claims: { email: 'user@example.com', name: 'User One' } });
		assert.match(contains({ ok: true }), res);
		assert.match('SID-TEST', res.data.sid);
		assert.match('user@example.com', res.data.email);
	});

	it('supplements a missing email via the UserInfo endpoint', () => {
		let res = run_verified({
			claims: {}, // no email in the ID token
			userinfo: resp(200, { sub: 'user-1', email: 'user@example.com', name: 'From UserInfo' }),
		});
		assert.match(contains({ ok: true }), res);
		assert.match('user@example.com', res.data.email);
	});

	it('returns IDENTITY_MISMATCH (403) when the UserInfo sub differs', () => {
		let res = run_verified({
			claims: {},
			userinfo: resp(200, { sub: 'someone-else', email: 'user@example.com' }),
		});
		assert.match(contains({ ok: false, error: 'IDENTITY_MISMATCH' }), res);
		assert.match(403, res.details.http_status);
	});

	it('returns TOKEN_REPLAYED (403) when the access token was already registered', () => {
		let res = run_verified({
			claims: { email: 'user@example.com' },
			fs: { behavior: { mkdir: (path) => index(path, '/tokens') < 0 } }, // token lock dir creation fails
		});
		assert.match(contains({ ok: false, error: 'TOKEN_REPLAYED' }), res);
		assert.match(403, res.details.http_status);
	});

	it('returns USER_NOT_AUTHORIZED (403) when no role matches', () => {
		let res = run_verified({ claims: { email: 'nobody@example.com', groups: [] } });
		assert.match(contains({ ok: false, error: 'USER_NOT_AUTHORIZED' }), res);
		assert.match(403, res.details.http_status);
	});

	it('returns UBUS_LOGIN_FAILED (500) when session creation fails', () => {
		let res = run_verified({
			claims: { email: 'user@example.com' },
			ubus_create_res: Result.err('UBUS_SESSION_FAILED'),
		});
		assert.match(contains({ ok: false, error: 'UBUS_LOGIN_FAILED' }), res);
		assert.match(500, res.details.http_status);
	});

	it('authorizes a user by group claim when email does not match', () => {
		let res = run_verified({ claims: { email: 'stranger@example.com', groups: ['ops-team'] } });
		assert.match(contains({ ok: true }), res);
		assert.match('SID-TEST', res.data.sid);
	});
});
