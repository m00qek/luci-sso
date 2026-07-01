import { describe, it, prop, gen, assert, truthy, falsy, contains, spy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Integration bucket — enter at handshake.initiate / handshake.authenticate with
// a full deps graph built by with_context (real oidc + discovery + session +
// ubus + config subgraph, faked system boundary, REAL native crypto). ID tokens
// are genuinely signed via lib.helpers.generate_id_token so signature
// verification runs for real — no verify stubs. Consolidates the tier2
// handshake_* suites plus initiate / request-validation coverage.

const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

// Config whose discovery resolves to the mocked issuer origin (internal == public).
function base_config(over) {
	return { ...f.MOCK_CONFIG, internal_issuer_url: f.MOCK_CONFIG.issuer_url, ...(over || {}) };
}

const DISCOVERY_URL = f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration";

// ─── initiate ────────────────────────────────────────────────────────────────

describe('handshake: initiate', () => {
	it('returns an auth URL and opaque token on success', () => {
		with_context({
			fs:          { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: { data: { [DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = handshake.initiate(deps, base_config());
			assert.match(truthy(), res.ok, `initiate failed: ${res.error}`);
			assert.match(0, index(res.data.url, f.MOCK_DISCOVERY.authorization_endpoint));
			assert.match(true, index(res.data.url, 'state=') >= 0);
			assert.match(true, index(res.data.url, 'nonce=') >= 0);
			assert.match(true, index(res.data.url, 'code_challenge=') >= 0);
			assert.match(true, index(res.data.url, 'code_challenge_method=S256') >= 0);
			assert.match(true, length(res.data.token) > 0);
		});
	});

	it('returns OIDC_DISCOVERY_FAILED (500) when discovery fails', () => {
		with_context({
			fs:          { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: { data: { [DISCOVERY_URL]: { status: 500, body: {} } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = handshake.initiate(deps, base_config());
			assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
			assert.match(500, res.details.http_status);
		});
	});

	prop('returns OIDC_DISCOVERY_FAILED for any non-HTTPS issuer_url (no fetch)',
		gen.string({ max_len: 30 }),
		(host, ctx) => {
			with_context({
				fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
				clock: { data: { now: 1516239022 } }
			}, (deps) => {
				let cfg = base_config({ issuer_url: `http://${host}`, internal_issuer_url: `http://${host}` });
				assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), handshake.initiate(deps, cfg));
			});
		}
	);
});

// ─── authenticate: request validation (pre-flight, before any HTTP) ────────────

describe('handshake: authenticate — request validation', () => {
	it('returns IDP_ERROR (400) when the IdP reports an error', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: { error: 'access_denied' }, cookies: {} };
			let res = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
			assert.match(contains({ ok: false, error: 'IDP_ERROR' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_CODE (400) when the authorization code is absent', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: {}, cookies: { '__Host-luci_sso_state': 'handle' } };
			let res = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
			assert.match(contains({ ok: false, error: 'MISSING_CODE' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_HANDSHAKE_COOKIE (401) when the state cookie is absent', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: { code: 'authcode' }, cookies: {} };
			let res = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
			assert.match(contains({ ok: false, error: 'MISSING_HANDSHAKE_COOKIE' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('returns STATE_NOT_FOUND (401) when the handshake handle does not exist', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: { code: 'authcode', state: 'whatever' }, cookies: { '__Host-luci_sso_state': 'ghosthandle' } };
			let res = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('returns STATE_PARAMETER_MISMATCH (403) when the query state does not match', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let hs = session.create_state(deps).data;
			let request = { query: { code: 'authcode', state: 'WRONG-STATE' }, cookies: { '__Host-luci_sso_state': hs.token } };
			let res = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
			assert.match(contains({ ok: false, error: 'STATE_PARAMETER_MISMATCH' }), res);
			assert.match(403, res.details.http_status);
		});
	});

	prop('never throws and always returns a failed Result for an unknown handle',
		gen.string({ max_len: 40 }),
		(code, ctx) => {
			ctx.classify('empty code', length(code) == 0);
			with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
				let request = { query: { code: code, state: 'x' }, cookies: { '__Host-luci_sso_state': 'ghosthandle' } };
				assert.match(contains({ ok: false }), handshake.authenticate(deps, base_config(), request, TEST_POLICY));
			});
		}
	);
});

// ─── authenticate: OAuth flow failures ─────────────────────────────────────────

describe('handshake: authenticate — OAuth flow failures', () => {
	// Seeds a real handshake and drives authenticate; the token/jwks failures all
	// occur before ID-token verification, so no signed id_token is needed.
	function run(http_cfg) {
		let out;
		with_context({
			fs:          { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: http_cfg,
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let hs = session.create_state(deps).data;
			let request = { query: { code: 'authcode', state: hs.state }, cookies: { '__Host-luci_sso_state': hs.token } };
			out = handshake.authenticate(deps, base_config(), request, TEST_POLICY);
		});
		return out;
	}

	it('returns OIDC_DISCOVERY_FAILED (500) when discovery fails in the callback', () => {
		let res = run({ data: { [DISCOVERY_URL]: { status: 503, body: {} } } });
		assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
		assert.match(500, res.details.http_status);
	});

	it('propagates TOKEN_EXCHANGE_FAILED when the token endpoint errors', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 500, body: {} }
		} });
		assert.match(contains({ ok: false, error: 'TOKEN_EXCHANGE_FAILED' }), res);
	});

	it('propagates OIDC_INVALID_GRANT (400) on an invalid_grant token response', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: 'invalid_grant' } }
		} });
		assert.match(contains({ ok: false, error: 'OIDC_INVALID_GRANT' }), res);
		assert.match(400, res.details.http_status);
	});

	it('returns JWKS_FETCH_FAILED (500) when the JWKS endpoint errors', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 200, body: { id_token: 'a.b.c', access_token: 'at' } },
			[f.MOCK_DISCOVERY.jwks_uri]: { status: 500, body: {} }
		} });
		assert.match(contains({ ok: false, error: 'JWKS_FETCH_FAILED' }), res);
		assert.match(500, res.details.http_status);
	});

	it('DO NOT retry JWKS refresh if kid is missing', () => {
		let access_token = "access-token-123";
		let test_config = base_config({ redirect_uri: "https://r/c" });

		let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
		let jwks = { keys: [ f.MOCK_JWK ] };
		let call_count = 0;
		let pending_tokens = { access_token: null, id_token: null };

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration")
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						if (url == jwks_uri) {
							call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", jwks) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), state_res.ok);
			let s_data = state_res.data;

			let payload = { ...f.MOCK_CLAIMS, nonce: s_data.nonce };
			pending_tokens.access_token = access_token;
			pending_tokens.id_token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", null);

			let request = {
				query: { code: "c1", state: s_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(falsy(), res.ok, "Handshake should fail due to invalid signature");
			assert.match("ID_TOKEN_VERIFICATION_FAILED", res.error);
			assert.match("INVALID_SIGNATURE", res.details?.details);
			assert.match(1, call_count, "JWKS should have been fetched exactly once (no retry when kid is missing)");
		});
	});
});

// ─── authenticate: recovery (JWKS rotation) ────────────────────────────────────

describe('handshake: recovery', () => {
	it('handle JWKS key rotation with automatic retry', () => {
		let access_token = "access-token-123";
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [
				{ name: "r1", emails: ["user-123"], read: ["*"], write: ["*"] }
			]
		};

		let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
		let old_jwks = { keys: [ f.MOCK_JWK ] };
		let new_jwks = { keys: [ f.ROTATION_NEW_JWK ] };
		let call_count = 0;

		let pending_tokens = { access_token: null, id_token: null };

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration")
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						if (url == jwks_uri) {
							call_count++;
							let data = (call_count == 1) ? old_jwks : new_jwks;
							return { ok: true, data: { status: 200, body: sprintf("%J", data) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), state_res.ok);
			let s_data = state_res.data;

			let payload = {
				...f.MOCK_CLAIMS,
				email: "user-123",
				nonce: s_data.nonce,
				at_hash: encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data
			};
			pending_tokens.access_token = access_token;
			pending_tokens.id_token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", f.ROTATION_NEW_JWK.kid);

			let request = {
				query: { code: "c1", state: s_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed after JWKS retry (Error: ${res.error}, Details: ${res.details})`);
			assert.match(2, call_count, "JWKS should have been fetched exactly twice (initial + forced refresh)");
		});
	});
});

// ─── authenticate: UserInfo supplementation ────────────────────────────────────

describe('handshake: userinfo', () => {
	it('supplements missing email when sub matches', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: "https://trusted.idp",
			internal_issuer_url: "https://trusted.idp",
			roles: [ { name: "admin", emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[f.MOCK_DISCOVERY.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed with UserInfo. Error: ${res.error}`);
			assert.match("user@example.com", res.data.email, "Email should be supplemented from UserInfo");
		});
	});

	it('fails identity binding when sub mismatches', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: "https://trusted.idp",
			internal_issuer_url: "https://trusted.idp"
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[f.MOCK_DISCOVERY.userinfo_endpoint]: { status: 200, body: { sub: "EVIL-SUB", email: "evil@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-456";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(falsy(), res.ok, "Handshake should fail on sub mismatch");
			assert.match("IDENTITY_MISMATCH", res.error);
		});
	});

	it('userinfo fallback succeeds after sub normalization (case-insensitive)', () => {
		let issuer_url = f.MOCK_CONFIG.issuer_url;
		let discovery_doc = {
			...f.MOCK_DISCOVERY,
			authorization_endpoint: "https://trusted.idp/auth",
			token_endpoint: "https://trusted.idp/token",
			jwks_uri: "https://trusted.idp/jwks",
			userinfo_endpoint: "https://trusted.idp/userinfo"
		};

		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: "https://trusted.idp",
			roles: [ { name: "admin", emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
		};

		let nonce_captured = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: "USER-123", email: "user@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						// ID Token has lowercase sub; UserInfo returns UPPERCASE sub — normalization must reconcile
						let payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: null, nonce: nonce_captured, at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), s_res.ok, `initiate failed: ${s_res.error}`);

			nonce_captured = replace(s_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_in_url = replace(s_res.data.url, /^.*state=([^&]+).*$/, "$1");

			let request = {
				query: { code: "c123", state: state_in_url },
				cookies: { "__Host-luci_sso_state": s_res.data.token }
			};

			let res = handshake.authenticate(deps, test_config, request, TEST_POLICY);
			assert.match(truthy(), res.ok, "Should SUCCEED after sub normalization fix");
			assert.match("user@example.com", res.data.email);
		});
	});
});

// ─── authenticate: split-horizon (internal vs public issuer) ───────────────────

describe('handshake: split-horizon', () => {
	it('prevents path corruption when issuer_url is in path', () => {
		let issuer_url = "https://auth.com";
		let internal_issuer_url = "https://internal.lan:8443";

		let discovery_doc = {
			issuer: issuer_url,
			authorization_endpoint: issuer_url + "/auth",
			token_endpoint: issuer_url + "/realms/auth.com/token",
			jwks_uri: issuer_url + "/realms/auth.com/jwks",
			userinfo_endpoint: issuer_url + "/realms/auth.com/userinfo"
		};

		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: issuer_url,
			internal_issuer_url: internal_issuer_url,
			redirect_uri: "https://router/callback",
			roles: [
				{ name: "admin", emails: ["admin@example.com"], read: ["*"], write: ["*"] }
			]
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/realms/auth.com/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == internal_issuer_url + "/realms/internal.lan:8443/token") {
							return { ok: true, data: { status: 404, body: "Path Corrupted" } };
						}
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = {
							...f.MOCK_CLAIMS,
							iss: issuer_url,
							email: "admin@example.com",
							nonce: "test-nonce",
							at_hash
						};
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok, `create_state failed: ${s_res.error}`);
			let s_data = s_res.data;
			let handle = s_data.token;
			let path = "/var/run/luci-sso/handshake_" + handle + ".json";

			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": handle }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed. Error: ${res.error} Details: ${res.details}`);
			assert.match("admin@example.com", res.data.email);
		});
	});

	it('prevents corruption when internal_issuer_url is substring of issuer_url', () => {
		let issuer_url = "https://auth.com";
		let internal_issuer_url = "https://auth";

		let discovery_doc = {
			issuer: issuer_url,
			authorization_endpoint: issuer_url + "/auth",
			token_endpoint: issuer_url + "/token",
			jwks_uri: issuer_url + "/jwks"
		};

		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: issuer_url,
			internal_issuer_url: internal_issuer_url,
			redirect_uri: "https://router/callback",
			roles: [ { name: "admin", emails: ["admin@example.com"], read: ["*"], write: ["*"] } ]
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s456" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-456";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = {
							...f.MOCK_CLAIMS,
							iss: issuer_url,
							email: "admin@example.com",
							nonce: "test-nonce",
							at_hash
						};
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed. Error: ${res.error}`);
		});
	});

	it('handles trailing slash in issuer_url (Audit W3)', () => {
		let issuer_url = "https://idp.com/";
		let internal_issuer_url = "https://internal.lan";

		let discovery_doc = {
			issuer: "https://idp.com",
			authorization_endpoint: "https://idp.com/auth",
			token_endpoint: "https://idp.com/token",
			jwks_uri: "https://idp.com/jwks"
		};

		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: issuer_url,
			internal_issuer_url: internal_issuer_url,
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[internal_issuer_url + "/token"]: { status: 200, body: { access_token: "at", id_token: "it" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			// If W3 bug existed, token_endpoint would be corrupted and GET would die in strict mode.
			// Reaching authenticate without strict-mode death confirms correct URL routing.
			handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), true);
		});
	});
});

// ─── authenticate: access-token lifetime warning ───────────────────────────────

describe('handshake: warning', () => {
	it('log warning for long-lived access tokens (W2)', () => {
		let now = 1516239022;
		let payload = { iat: now, exp: now + 90000 };
		let long_lived_token = "header." + encoding.b64url_encode(sprintf("%J", payload)).data + ".signature";

		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
		};

		let log_calls = [];
		let nonce_ref = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, long_lived_token).data, 0, 16)).data;
						let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_ref, at_hash };
						let id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: long_lived_token, id_token }) } };
					}
				}
			},
			clock: { data: { now } }
		}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);

			let state_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), state_res.ok, `initiate failed: ${state_res.error}`);

			nonce_ref = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");

			let request = {
				query: { code: "c1", state: state_val },
				cookies: { "__Host-luci_sso_state": state_res.data.token }
			};

			let auth_res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), auth_res.ok, `authenticate failed: ${auth_res.error} ${auth_res.details}`);
		});

		let found = false;
		for (let e in log_calls) {
			if (e[0] == "warn" && match(e[1], /Access token lifetime exceeds 24h replay window/)) {
				found = true;
				break;
			}
		}
		assert.match(truthy(), found, "Should log warning for long-lived access token");
	});

	it('silent for opaque or short-lived tokens', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
		};

		let cases = [
			{ name: "Opaque", token: "opaque_string_without_dots" },
			{ name: "Short-lived", token: "h." + encoding.b64url_encode(sprintf("%J", { iat: 100, exp: 200 })).data + ".s" }
		];

		for (let c in cases) {
			let log_calls = [];
			let nonce_ref = null;
			let access_token = c.token;

			with_context({
				fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
				ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": {}, "session:set": {} } },
				http_client: {
					data: {
						[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
						[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
					},
					behavior: {
						post: (url, opts) => {
							let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
							let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_ref, at_hash };
							let id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
						}
					}
				},
				clock: { data: { now: 1516239022 } }
			}, (deps) => {
				deps.log = (level, msg) => push(log_calls, [level, msg]);

				let state_res = handshake.initiate(deps, test_config);
				assert.match(truthy(), state_res.ok, `[${c.name}] initiate failed: ${state_res.error}`);

				nonce_ref = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
				let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");

				let request = {
					query: { code: "c1", state: state_val },
					cookies: { "__Host-luci_sso_state": state_res.data.token }
				};

				let auth_res = handshake.authenticate(deps, test_config, request);
				assert.match(truthy(), auth_res.ok, `[${c.name}] authenticate failed: ${auth_res.error} ${auth_res.details}`);
			});

			let found = false;
			for (let e in log_calls) {
				if (e[0] == "warn" && match(e[1], /Access token lifetime exceeds 24h replay window/)) {
					found = true;
					break;
				}
			}
			assert.match(falsy(), found, `Should NOT log warning for ${c.name} token`);
		}
	});
});

// ─── security: one-time state consumption & capacity ───────────────────────────

describe('handshake: security', () => {
	it('state is consumed only once (B1)', () => {
		let handle = "valid-handle";
		let path = `/var/run/luci-sso/handshake_${handle}.json`;
		let config = { ...f.MOCK_CONFIG, clock_tolerance: 30 };

		let mock_handshake = {
			id: "h123",
			state: "state123",
			nonce: "nonce123",
			code_verifier: "verifier123-verifier123-verifier123-verifier123",
			iat: 1516239022,
			exp: 1516239022 + 300
		};

		let rename_calls_arr = null;
		let unlink_calls_arr = null;

		with_context({
			fs: { data: { [path]: sprintf("%J", mock_handshake) } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = {
				query: { code: "123", state: mock_handshake.state },
				cookies: { "__Host-luci_sso_state": handle }
			};

			handshake.authenticate(deps, config, req);

			rename_calls_arr = spy(deps.fs).calls.rename || [];
			unlink_calls_arr = spy(deps.fs).calls.unlink || [];
		});

		let rename_calls = 0;
		for (let c in rename_calls_arr) {
			if (index(c[0], handle) != -1) rename_calls++;
		}

		let remove_calls = 0;
		for (let c in unlink_calls_arr) {
			if (index(c[0], handle) != -1) remove_calls++;
		}

		assert.match(1, rename_calls, "Should attempt rename exactly once");
		assert.match(1, remove_calls, "Should attempt remove exactly once (inside verify_state)");
	});

	it('enforce hard capacity limit with emergency reap (DoS protection)', () => {
		let mtime = 1000;

		with_context({
			fs: {
				data: {},
				behavior: {
					stat: (path) => ({ mtime: mtime++ })
				}
			},
			clock: { data: { now: 0 } }
		}, (deps) => {
			for (let i = 0; i < 100; i++) {
				let res = session.create_state(deps);
				assert.match(truthy(), res.ok, `Failed to create handshake #${i}: ${res.error}`);
			}

			let files = deps.fs.lsdir("/var/run/luci-sso");
			let files_before = 0;
			for (let fn in files) if (match(fn, /^handshake_.*\.json$/)) files_before++;

			assert.match(100, files_before, "Should have exactly 100 handshake files");

			let res_101 = session.create_state(deps);
			assert.match(truthy(), res_101.ok, "101st handshake should succeed after emergency reap");

			files = deps.fs.lsdir("/var/run/luci-sso");
			let files_after = 0;
			for (let fn in files) if (match(fn, /^handshake_.*\.json$/)) files_after++;

			// Expected: 100 (original) - 50 (reaped) + 1 (new) = 51
			assert.match(51, files_after, "Emergency reap should have cleared 50% of oldest handshakes");
		});
	});
});

// ─── DoS / token registration ordering ─────────────────────────────────────────

describe('handshake: token registration ordering', () => {
	it('register_token deferred until after verification (DoS prevention)', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
		};

		with_context({
			fs: { data: {} },
			http_client: {
				behavior: {
					get: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: "at1", id_token: "invalid.id.token" }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), state_res.ok, "initiate should succeed");
			let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
			let request = {
				path: "/callback",
				query: { code: "c1", state: state_val },
				cookies: { "__Host-luci_sso_state": state_res.data.token },
				env: { HTTPS: "on" }
			};

			let auth_res = handshake.authenticate(deps, test_config, request, { allowed_algs: ["RS256"] });
			assert.match(falsy(), auth_res.ok, "Authentication should fail due to invalid ID token");

			let mkdir_calls = spy(deps.fs).calls.mkdir;
			let token_registered = false;
			for (let call in mkdir_calls) {
				if (call[0] && index(call[0], "/tokens/") != -1) {
					token_registered = true;
					break;
				}
			}
			assert.match(falsy(), token_registered, "Should NOT register token before successful ID token verification");
		});
	});
});

// ─── groups claim propagation (userinfo fallback) ───────────────────────────────

describe('handshake: reproduction', () => {
	it('userinfo fallback drops groups claim', () => {
		let issuer_url = f.MOCK_CONFIG.issuer_url;
		let discovery_doc = {
			...f.MOCK_DISCOVERY,
			authorization_endpoint: "https://trusted.idp/auth",
			token_endpoint: "https://trusted.idp/token",
			jwks_uri: "https://trusted.idp/jwks",
			userinfo_endpoint: "https://trusted.idp/userinfo"
		};
		let groups = ["idp-admin"];
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: "https://trusted.idp",
			roles: [ { name: "admin", groups: ["idp-admin"], emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
		};
		let nonce_ref = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]:          { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com", groups: groups } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == discovery_doc.token_endpoint) {
							let access_token = "at-123";
							let payload = {
								...f.MOCK_CLAIMS,
								email: null,
								groups: null,
								nonce: nonce_ref,
								at_hash: encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data
							};
							let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), s_res.ok, `initiate failed: ${s_res.error}`);
			nonce_ref = replace(s_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_val = replace(s_res.data.url, /^.*state=([^&]+).*$/, "$1");
			let request = {
				query: { code: "c123", state: state_val },
				cookies: { "__Host-luci_sso_state": s_res.data.token }
			};
			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Authentication should succeed (Error: ${res.error}, Details: ${res.details})`);
		});
	});
});
