import { describe, it, prop, gen, assert, truthy, falsy, contains, spy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as common from 'luci_sso.session.common';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context, rpcd_logins, UBUS_NO_DATA } from 'context';
import * as f from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Integration bucket — enter at handshake.initiate / handshake.authenticate with
// a full deps graph built by with_context (real oidc + discovery + session +
// ubus + config subgraph, faked system boundary, REAL native crypto). ID tokens
// are genuinely signed via lib.helpers.generate_id_token so signature
// verification runs for real — no verify stubs. Consolidates the tier2
// handshake_* suites plus initiate / request-validation coverage.


// Config whose discovery resolves to the mocked issuer origin (internal == public).
function base_config(over) {
	return { ...f.MOCK_CONFIG, internal_issuer_url: f.MOCK_CONFIG.issuer_url, ...(over || {}) };
}

const DISCOVERY_URL = f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration";

// ─── initiate ────────────────────────────────────────────────────────────────

describe('handshake: initiate', () => {
	it('returns an auth URL and opaque token on success', () => {
		with_context({
			fs:          { data: {} },
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

	it('returns OIDC_DISCOVERY_FAILED (502) when discovery fails', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { [DISCOVERY_URL]: { status: 500, body: {} } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = handshake.initiate(deps, base_config());
			assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
			assert.match(502, res.details.http_status);
		});
	});

	prop('returns OIDC_DISCOVERY_FAILED for any non-HTTPS issuer_url (no fetch)',
		gen.string({ max_len: 30 }),
		(host, ctx) => {
			with_context({
				fs:    { data: {} },
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
			let res = handshake.authenticate(deps, base_config(), request);
			assert.match(contains({ ok: false, error: 'IDP_ERROR' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_CODE (400) when the authorization code is absent', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: {}, cookies: { '__Host-luci_sso_state': 'handle' } };
			let res = handshake.authenticate(deps, base_config(), request);
			assert.match(contains({ ok: false, error: 'MISSING_CODE' }), res);
			assert.match(400, res.details.http_status);
		});
	});

	it('returns MISSING_HANDSHAKE_COOKIE (401) when the state cookie is absent', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: { code: 'authcode' }, cookies: {} };
			let res = handshake.authenticate(deps, base_config(), request);
			assert.match(contains({ ok: false, error: 'MISSING_HANDSHAKE_COOKIE' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('returns STATE_NOT_FOUND (401) when the handshake handle does not exist', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let request = { query: { code: 'authcode', state: 'whatever' }, cookies: { '__Host-luci_sso_state': 'ghosthandle' } };
			let res = handshake.authenticate(deps, base_config(), request);
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), res);
			assert.match(401, res.details.http_status);
		});
	});

	it('a forged callback (wrong state) keeps the pending login usable', () => {
		// The state cookie is SameSite=Lax, so a cross-site top-level GET to
		// /callback carries it. With a wrong state, the handshake must survive
		// so the victim's real callback still works.
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let path = `/var/run/luci-sso/handshake_${hs.token}.json`;
			let forged = { query: { code: 'attacker', state: 'WRONG-STATE' }, cookies: { '__Host-luci_sso_state': hs.token } };

			let res = handshake.authenticate(deps, base_config(), forged);
			assert.match(contains({ ok: false, error: 'STATE_PARAMETER_MISMATCH' }), res);
			assert.match(403, res.details.http_status);
			assert.match(truthy(), deps.fs.readfile(path), 'the handshake file is still there');
			assert.match(contains({ ok: true }), session.verify_state(deps, hs.token, hs.state, 300), 'the real state still verifies');
		});
	});

	it('returns STATE_PARAMETER_MISMATCH (403) when the query state does not match', () => {
		with_context({ fs: { data: {} }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let request = { query: { code: 'authcode', state: 'WRONG-STATE' }, cookies: { '__Host-luci_sso_state': hs.token } };
			let res = handshake.authenticate(deps, base_config(), request);
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
				assert.match(contains({ ok: false }), handshake.authenticate(deps, base_config(), request));
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
			fs:          { data: {} },
			http_client: http_cfg,
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let request = { query: { code: 'authcode', state: hs.state }, cookies: { '__Host-luci_sso_state': hs.token } };
			out = handshake.authenticate(deps, base_config(), request);
		});
		return out;
	}

	it('returns OIDC_DISCOVERY_FAILED (502) when discovery fails in the callback', () => {
		let res = run({ data: { [DISCOVERY_URL]: { status: 503, body: {} } } });
		assert.match(contains({ ok: false, error: 'OIDC_DISCOVERY_FAILED' }), res);
		assert.match(502, res.details.http_status);
	});

	it('returns TOKEN_EXCHANGE_FAILED (502), not the IdP status, when the token endpoint errors', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 401, body: { error: 'invalid_client' } }
		} });
		assert.match(contains({ ok: false, error: 'TOKEN_EXCHANGE_FAILED' }), res);
		assert.match(502, res.details.http_status);
	});

	it('returns TOKEN_ENDPOINT_NETWORK_ERROR (502) when the token endpoint is unreachable', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { error: 'CONNECTION_FAILED' }
		} });
		assert.match(contains({ ok: false, error: 'TOKEN_ENDPOINT_NETWORK_ERROR' }), res);
		assert.match(502, res.details.http_status);
	});

	it('returns OIDC_INVALID_GRANT (502) on an invalid_grant token response', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: 'invalid_grant' } }
		} });
		assert.match(contains({ ok: false, error: 'OIDC_INVALID_GRANT' }), res);
		assert.match(502, res.details.http_status);
	});

	it('returns JWKS_FETCH_FAILED (502) when the JWKS endpoint errors', () => {
		let res = run({ data: {
			[DISCOVERY_URL]: { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.token_endpoint]: { status: 200, body: { id_token: 'a.b.c', access_token: 'at' } },
			[f.MOCK_DISCOVERY.jwks_uri]: { status: 500, body: {} }
		} });
		assert.match(contains({ ok: false, error: 'JWKS_FETCH_FAILED' }), res);
		assert.match(502, res.details.http_status);
	});

	it('DO NOT retry JWKS refresh if kid is missing', () => {
		let access_token = "access-token-123";
		let test_config = base_config({ redirect_uri: "https://r/c" });

		let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
		let jwks = { keys: [ f.MOCK_JWK ] };
		let call_count = 0;
		let pending_tokens = { access_token: null, id_token: null };

		with_context({
			fs:    { data: {} },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration")
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						if (url == jwks_uri) {
							call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", jwks) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
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
				{ name: "r1", emails: ["user-123"] }
			]
		};

		let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
		let old_jwks = { keys: [ f.MOCK_JWK ] };
		let new_jwks = { keys: [ f.ROTATION_NEW_JWK ] };
		let call_count = 0;

		let pending_tokens = { access_token: null, id_token: null };

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ r1: { read: ["*"], write: ["*"] } }) },
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
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
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
			roles: [ { name: "admin", emails: ["user@example.com"] } ]
		};

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[f.MOCK_DISCOVERY.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com", email_verified: true } }
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
			let s_res = session.create_state(deps, 0);
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
			fs:    { data: {} },
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
			let s_res = session.create_state(deps, 0);
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

	// Runs a full callback where the ID token carries id_sub and no email, so
	// the handshake falls back to UserInfo, which answers with userinfo_sub.
	// ui_entry, when given, replaces the UserInfo endpoint's whole mock entry.
	let run_userinfo_sub = (id_sub, userinfo_sub, ui_entry, logs) => {
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
			roles: [ { name: "admin", emails: ["user@example.com"] } ]
		};

		let nonce_captured = null;
		let res = null;

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: ui_entry ?? { status: 200, body: { sub: userinfo_sub, email: "user@example.com", email_verified: true } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, sub: id_sub, email: null, nonce: nonce_captured, at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			if (logs) deps.log = (l, m) => push(logs, [ l, m ]);
			let s_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), s_res.ok, `initiate failed: ${s_res.error}`);

			nonce_captured = replace(s_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_in_url = replace(s_res.data.url, /^.*state=([^&]+).*$/, "$1");

			let request = {
				query: { code: "c123", state: state_in_url },
				cookies: { "__Host-luci_sso_state": s_res.data.token }
			};

			res = handshake.authenticate(deps, test_config, request);
		});
		return res;
	};

	it('accepts a UserInfo sub that is byte-for-byte the ID token sub', () => {
		let res = run_userinfo_sub("user-123", "user-123");
		assert.match(truthy(), res.ok, `Handshake should succeed. Error: ${res.error}`);
		assert.match("user@example.com", res.data.email);
	});

	it('rejects a UserInfo sub that differs only in case (sub is case-sensitive, OIDC Core §5.3.2)', () => {
		let res = run_userinfo_sub("user-123", "USER-123");
		assert.match(falsy(), res.ok, "A sub differing only in case is a different subject");
		assert.match("IDENTITY_MISMATCH", res.error);
		assert.match({ http_status: 403 }, res.details);
	});

	it('refuses the login with IDENTITY_MISMATCH (403) when the UserInfo sub is missing, a number or empty (OIDC Core §5.3.2)', () => {
		let email = "user@example.com";
		let entries = {
			"missing": { status: 200, body: { email, email_verified: true } },
			"null":    { status: 200, body: { sub: null, email, email_verified: true } },
			"number":  { status: 200, body: { sub: 123, email, email_verified: true } },
			"empty":   { status: 200, body: { sub: "", email, email_verified: true } },
			"array":   { status: 200, body: "[\"123\"]" }
		};
		for (let name, entry in entries) {
			let logs = [];
			let res = run_userinfo_sub("123", null, entry, logs);
			assert.match(contains({ ok: false, error: "IDENTITY_MISMATCH" }), res, `UserInfo sub ${name}`);
			assert.match({ http_status: 403 }, res.details, `UserInfo sub ${name}`);
			assert.match(1, length(filter(logs, (e) => e[0] == "error" && index(e[1], "UserInfo 'sub' mismatch [session_id: ") == 0)), `UserInfo sub ${name}: ${sprintf("%J", logs)}`);
		}
	});

	it('a failed UserInfo fetch is logged as a warning and the login goes on with the ID token claims', () => {
		// No email from either source, so the login ends at role matching,
		// not at IDENTITY_MISMATCH.
		let entries = {
			"USERINFO_NETWORK_ERROR": { error: "CONNECTION_FAILED" },
			"USERINFO_FETCH_FAILED":  { status: 401, body: { sub: "123" } },
			"USERINFO_INVALID_JSON":  { status: 200, body: "not json" }
		};
		for (let code, entry in entries) {
			let logs = [];
			let res = run_userinfo_sub("123", null, entry, logs);
			assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED" }), res, code);
			assert.match(1, length(filter(logs, (e) => e[0] == "warn" && index(e[1], "UserInfo fallback failed [session_id: ") == 0 && index(e[1], `]: ${code}`) > 0)), `${code}: ${sprintf("%J", logs)}`);
		}
	});
});

// ─── authenticate: split-horizon (internal vs public issuer) ───────────────────

describe('handshake: restricted roles', () => {
	it('a restricted role receives the expanded ACL grants, not just access-group names', () => {
		// Full callback for a role that may only read luci-base and write
		// luci-mod-system-config. The ACL files are the real format; the grants
		// that reach session.grant must be the expanded scopes (rpcd's rules).
		let acl = {
			"/usr/share/rpcd/acl.d/luci-base.json": sprintf("%J", {
				"luci-base": { read: { ubus: { luci: [ "getVersion" ] }, uci: [ "luci" ] }, write: { uci: [ "luci" ] } }
			}),
			"/usr/share/rpcd/acl.d/luci-mod-system.json": sprintf("%J", {
				"luci-mod-system-config": { read: { uci: [ "system" ] }, write: { ubus: { rc: [ "init" ] }, uci: [ "system" ] } },
				"luci-mod-system-reboot": { write: { ubus: { system: [ "reboot" ] } } }
			}),
		};
		let config = {
			...f.MOCK_CONFIG, internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			roles: [ { name: "operator", emails: [ "admin@example.com" ], groups: [] } ]
		};
		let grants = null, result = null;

		with_context({
			fs: { data: acl },
			ubus: { data: { "session:create": { "ubus_rpc_session": "s-op" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ operator: { read: [ "luci-base" ], write: [ "luci-mod-system-config" ] } }) },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-operator";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let claims = { ...f.MOCK_CLAIMS, email: "admin@example.com", nonce: "test-nonce", at_hash };
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(claims, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			result = handshake.authenticate(deps, config, { query: { code: "c", state: raw.state }, cookies: { "__Host-luci_sso_state": hs.token } });
			grants = [];
			for (let c in filter(spy(deps.ubus).calls.call, (c) => c[1] == "grant"))
				for (let o in c[2].objects) push(grants, `${c[2].scope} ${o[0]} ${o[1]}`);
			grants = sort(grants);
		});

		assert.match(contains({ ok: true }), result, `${result.error} ${result.details}`);
		assert.match(sort([
			"access-group luci-base read", "ubus luci getVersion", "uci luci read",
			"access-group luci-mod-system-config read", "uci system read",
			"access-group luci-mod-system-config write", "ubus rc init", "uci system write",
		]), grants);
	});
});

// ─── authenticate: at_hash (OIDC Core §3.1.3.6 / §3.1.3.8) ────────────────────

describe('handshake: authenticate — at_hash', () => {
	// Runs a full callback whose ID token carries `at_hash` as given (null:
	// no claim at all). Returns the result and whether a session was created.
	function login(at_hash_of) {
		let out = { result: null, created: false };
		with_context({
			fs:   { data: {} },
			uci:  { data: rpcd_logins({ admin: { read: [ "*" ], write: [ "*" ] } }) },
			ubus: { data: {
				"session:create": () => { out.created = true; return { ubus_rpc_session: "s-at-hash" }; },
				"session:grant":  UBUS_NO_DATA,
				"session:set":    UBUS_NO_DATA,
			} },
			http_client: {
				data: {
					[DISCOVERY_URL]:             { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-binding";
						let payload = { ...f.MOCK_CLAIMS, email: "admin@example.com", nonce: "test-nonce" };
						let at_hash = at_hash_of(access_token);
						if (at_hash != null) payload.at_hash = at_hash;
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			let config = base_config({ roles: [ { name: "admin", emails: [ "admin@example.com" ], groups: [] } ] });
			out.result = handshake.authenticate(deps, config,
				{ query: { code: "c", state: raw.state }, cookies: { "__Host-luci_sso_state": hs.token } });
		});
		return out;
	}

	let hash_of = (token) => encoding.b64url_encode(substr(crypto.hash_sha256(native, token).data, 0, 16)).data;

	it('an ID token without at_hash logs the user in', () => {
		let r = login((at) => null);
		assert.match(contains({ ok: true }), r.result, `${r.result.error} ${r.result.details?.details}`);
		assert.match(true, r.created);
	});

	it('an ID token whose at_hash matches the access token logs the user in', () => {
		let r = login((at) => hash_of(at));
		assert.match(contains({ ok: true }), r.result, `${r.result.error} ${r.result.details?.details}`);
		assert.match(true, r.created);
	});

	it('an ID token whose at_hash does not match is refused with AT_HASH_MISMATCH, and no session is created', () => {
		let r = login((at) => hash_of("a-substituted-access-token"));
		assert.match(contains({ ok: false, error: "ID_TOKEN_VERIFICATION_FAILED", details: contains({ details: "AT_HASH_MISMATCH", http_status: 401 }) }), r.result);
		assert.match(false, r.created);
	});
});

// ─── authenticate: role selection and the role's rpcd login entry ─────────────

describe('handshake: role selection', () => {
	// Runs a full callback for a user with the given claims against `roles`
	// and the rpcd sections in `rpcd`, with the sub rules made for the
	// configured issuer unless `over` says otherwise. Returns the result, the
	// session values set, whether a session was created, and the log lines.
	function login(roles, rpcd, claims, over) {
		let out = { result: null, values: null, created: false, logs: [] };
		with_context({
			fs:   { data: {} },
			uci:  { data: { rpcd } },
			ubus: { data: {
				"session:create": () => { out.created = true; return { ubus_rpc_session: "s-role" }; },
				"session:grant":  UBUS_NO_DATA,
				"session:set":    (args) => { out.values = args.values; return UBUS_NO_DATA; },
			} },
			http_client: {
				data: {
					[DISCOVERY_URL]:           { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-role";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, ...claims, nonce: "test-nonce", at_hash };
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			deps.log = (l, m) => push(out.logs, m);
			let hs = session.create_state(deps, 0).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			out.result = handshake.authenticate(deps, base_config({ sub_issuer: f.MOCK_CONFIG.issuer_url, roles, ...(over || {}) }),
				{ query: { code: "c", state: raw.state }, cookies: { "__Host-luci_sso_state": hs.token } });
		});
		return out;
	}

	let entries = rpcd_logins({ staff: { read: [ "*" ] }, admins: { read: [ "*" ], write: [ "*" ] }, me: { read: [ "*" ] } }).rpcd;
	let claims = { email: "alice@example.com", groups: [ "staff", "admins" ] };

	it('the first matching role in config order wins, and the log names it and the other matches', () => {
		let roles = [
			{ name: "admins", emails: [], groups: [ "admins" ] },
			{ name: "nobody", emails: [ "bob@example.com" ], groups: [] },
			{ name: "staff", emails: [], groups: [ "staff" ] },
			{ name: "me", emails: [ "alice@example.com" ], groups: [] },
		];
		let r = login(roles, entries, claims);
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:admins", r.values.username, "the session is the first role's");
		assert.match(1, length(filter(r.logs, (m) => match(m, /mapped to role 'admins', the first match; also matched: staff, me \[session_id: /))));

		let reordered = login([ roles[3], roles[2], roles[0] ], entries, claims);
		assert.match("sso:me", reordered.values.username, "order, not privilege, decides");
	});

	it('a single match logs no other matches', () => {
		let r = login([ { name: "staff", emails: [], groups: [ "staff" ] } ], entries, claims);
		assert.match("sso:staff", r.values.username);
		assert.match(1, length(filter(r.logs, (m) => match(m, /mapped to role 'staff' \[session_id: /))));
	});

	it('a login matched by sub only: the email and groups match no role', () => {
		let roles = [
			{ name: "staff", emails: [ "alice@example.com" ], groups: [ "admins" ], subs: [] },
			{ name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] },
		];
		let r = login(roles, entries, { email: "stranger@example.com", groups: [ "nobody" ] });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:me", r.values.username);
		assert.match(1, length(filter(r.logs, (m) => match(m, /mapped to role 'me' \[session_id: /))));
		assert.match(0, length(filter(r.logs, (m) => index(m, f.MOCK_CLAIMS.sub) >= 0)), "the log never carries the raw sub");
	});

	it('a login whose email is not verified still matches by sub', () => {
		let r = login([ { name: "me", emails: [ "alice@example.com" ], groups: [], subs: [ f.MOCK_CLAIMS.sub ] } ], entries,
			{ email: "someone@example.com", email_verified: false });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:me", r.values.username);
	});

	it('a sub that differs only in case is refused with USER_NOT_AUTHORIZED (403), which carries the sub for the error page', () => {
		let r = login([ { name: "me", emails: [], groups: [], subs: [ uc(f.MOCK_CLAIMS.sub) ] } ], entries, { email: "stranger@example.com" });
		assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED" }), r.result);
		assert.match({ http_status: 403, subject: f.MOCK_CLAIMS.sub }, r.result.details);
		assert.match(false, r.created, "no session");
		assert.match(0, length(filter(r.logs, (m) => index(m, f.MOCK_CLAIMS.sub) >= 0)), "the log never carries the raw sub");
	});

	it('logs no sub_issuer warning while the sub rules count', () => {
		let r = login([ { name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] } ], entries, { email: "stranger@example.com" });
		assert.match("sso:me", r.values.username);
		assert.match(0, length(filter(r.logs, (m) => index(m, "Ignoring sub rules") == 0)));
	});

	// OIDC Core §5.7: a sub is unique only within its issuer. After issuer_url
	// changes, sub_issuer still names the old issuer, and a rule made for an
	// account there must not let in whoever the new issuer calls by that sub.
	const OLD = "https://old-idp.example.com";
	const WARNING = `Ignoring sub rules: sub_issuer '${OLD}' does not match issuer_url '${f.MOCK_CONFIG.issuer_url}' [session_id: `;
	let warned = (r) => length(filter(r.logs, (m) => index(m, WARNING) == 0));

	it('after issuer_url changes: a login the sub rule let in falls through to the group or email rule', () => {
		let roles = [
			{ name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] },
			{ name: "staff", emails: [], groups: [ "staff" ], subs: [] },
		];
		let claims = { email: "stranger@example.com", groups: [ "staff" ] };
		let before = login(roles, entries, claims);
		assert.match("sso:me", before.values.username, "the sub rule, while it is bound to issuer_url");

		let after = login(roles, entries, claims, { sub_issuer: OLD });
		assert.match(contains({ ok: true }), after.result, `${after.result.error}`);
		assert.match("sso:staff", after.values.username, "the group rule");
		assert.match(1, warned(after), "the warning names both issuers");

		let by_email = login([ roles[0], { name: "staff", emails: [ "alice@example.com" ], groups: [], subs: [] } ], entries,
			{ email: "alice@example.com", email_verified: true }, { sub_issuer: OLD });
		assert.match("sso:staff", by_email.values.username, "the email rule");
	});

	it('after issuer_url changes: a login only the sub rule let in is refused with USER_NOT_AUTHORIZED (403), and the warning says why', () => {
		let r = login([ { name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] } ], entries,
			{ email: "stranger@example.com", groups: [ "nobody" ] }, { sub_issuer: OLD });
		assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED" }), r.result);
		assert.match({ http_status: 403, subject: f.MOCK_CLAIMS.sub }, r.result.details);
		assert.match(false, r.created, "no session");
		assert.match(1, warned(r));
	});

	it('after issuer_url changes: a sub_issuer that differs only in a trailing slash is another issuer', () => {
		let r = login([ { name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] } ], entries,
			{ email: "stranger@example.com" }, { sub_issuer: f.MOCK_CONFIG.issuer_url + "/" });
		assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED" }), r.result);
	});

	it('an unset sub_issuer ignores the sub rules too, and the warning says it is not set', () => {
		let r = login([ { name: "me", emails: [], groups: [], subs: [ f.MOCK_CLAIMS.sub ] } ], entries,
			{ email: "stranger@example.com" }, { sub_issuer: null });
		assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED" }), r.result);
		assert.match(1, length(filter(r.logs, (m) => index(m, "Ignoring sub rules: sub_issuer is not set [session_id: ") == 0)));
	});

	it("fails with UBUS_LOGIN_FAILED (500) and no session when the chosen role has no rpcd login entry", () => {
		// "root" is the stock rpcd login's user, never a role's entry.
		let r = login([ { name: "root", emails: [ "alice@example.com" ], groups: [] } ],
			{ root: { ".type": "login", username: "root", password: "$p$root", read: [ "*" ], write: [ "*" ] } }, claims);
		assert.match(contains({ ok: false, error: "UBUS_LOGIN_FAILED", details: { http_status: 500 } }), r.result);
		assert.match(false, r.created);
		assert.match(1, length(filter(r.logs, (m) => index(m, "MISSING_RPCD_LOGIN: role 'root'") == 0)));
	});

	it("fails with UBUS_LOGIN_FAILED (500) and no session when the role's entry has a password", () => {
		let rpcd = { luci_sso_staff: { ...entries.luci_sso_staff, password: "" } };
		let r = login([ { name: "staff", emails: [], groups: [ "staff" ] } ], rpcd, claims);
		assert.match(contains({ ok: false, error: "UBUS_LOGIN_FAILED", details: { http_status: 500 } }), r.result);
		assert.match(false, r.created);
		assert.match(1, length(filter(r.logs, (m) => index(m, "INSECURE_RPCD_LOGIN: rpcd login entry 'luci_sso_staff'") == 0)));
	});
});

// ─── authenticate: email_verified and require_email_verified ─────────────────

describe('handshake: email_verified', () => {
	// Runs a full callback. `id` is merged over the fixture claims (whose
	// email_verified is true); a key set to null is left out of the ID token.
	// `userinfo` is the UserInfo body (null: the endpoint is not mocked, so a
	// fetch fails). Returns the result, whether a session was created, the
	// session's username, the log lines and the URLs fetched.
	function login(id, userinfo, over) {
		let out = { result: null, created: false, username: null, values: null, logs: [], fetched: [] };
		let http = {
			[DISCOVERY_URL]:             { status: 200, body: f.MOCK_DISCOVERY },
			[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
		};
		if (userinfo) http[f.MOCK_DISCOVERY.userinfo_endpoint] = { status: 200, body: { sub: f.MOCK_CLAIMS.sub, ...userinfo } };
		with_context({
			fs:   { data: {} },
			uci:  { data: rpcd_logins({ admin: { read: [ "*" ], write: [ "*" ] }, staff: { read: [ "*" ] } }) },
			ubus: { data: {
				"session:create": () => { out.created = true; return { ubus_rpc_session: "s-ev" }; },
				"session:grant":  UBUS_NO_DATA,
				"session:set":    (args) => { out.username = args.values.username; out.values = args.values; return UBUS_NO_DATA; },
			} },
			http_client: {
				data: http,
				behavior: {
					post: (url, opts) => {
						let access_token = "at-email-verified";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, ...id, nonce: "test-nonce", at_hash };
						for (let k in keys(payload)) if (payload[k] == null) delete payload[k];
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			deps.log = (l, m) => push(out.logs, [ l, m ]);
			let get = deps.http.get;
			deps.http.get = (url, opts) => { push(out.fetched, url); return get(url, opts); };
			let hs = session.create_state(deps, 0).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			let roles = [
				{ name: "admin", emails: [ "admin@example.com" ], groups: [] },
				{ name: "staff", emails: [], groups: [ "staff" ] },
			];
			out.result = handshake.authenticate(deps, base_config({ roles, ...(over || {}) }),
				{ query: { code: "c", state: raw.state }, cookies: { "__Host-luci_sso_state": hs.token } });
		});
		return out;
	}

	let warned = (r) => filter(r.logs, (l) => l[0] == "warn" && index(l[1], "Ignoring the unverified email of user [sub_id: ") == 0);
	let userinfo_fetched = (r) => index(r.fetched, f.MOCK_DISCOVERY.userinfo_endpoint) >= 0;
	let refused = (r) => {
		assert.match(contains({ ok: false, error: "USER_NOT_AUTHORIZED", details: { http_status: 403 } }), r.result);
		assert.match(false, r.created, "no session");
	};

	it('ID token: a verified email matches its role, with no warning', () => {
		let r = login({ email: "admin@example.com", email_verified: true });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:admin", r.username);
		assert.match(0, length(warned(r)));
	});

	it('ID token: an unverified or unflagged email, or the string "true", is refused through the no-role path, with a warning that never names the email', () => {
		for (let v in [ false, "false", "true", null ]) {
			let r = login({ email: "admin@example.com", email_verified: v });
			refused(r);
			let w = warned(r);
			assert.match(1, length(w), `${v}`);
			assert.match(true, match(w[0][1], /\[session_id: [0-9a-f]+\]$/) != null, "carries the session id");
			assert.match(1, length(filter(r.logs, (l) => index(l[1], "matched no roles") >= 0)), "the existing no-role log follows");
			for (let l in r.logs)
				assert.match(-1, index(l[1], "admin@example.com"), `the email is never logged: ${l[1]}`);
		}
	});

	it('ID token: a group still matches while the email is unverified', () => {
		let r = login({ email: "admin@example.com", email_verified: false, groups: [ "staff" ] });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:staff", r.username, "the group's role, not the email's");
		assert.match(1, length(warned(r)));
	});

	it('ID token: with require_email_verified off, an unverified email matches as before, with no warning', () => {
		let r = login({ email: "admin@example.com", email_verified: false }, null, { require_email_verified: false });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:admin", r.username);
		assert.match(0, length(warned(r)));
	});

	it('ID token: an unverified email is not replaced by UserInfo, whose flag is never borrowed', () => {
		let r = login({ email: "admin@example.com", email_verified: false }, { email: "admin@example.com", email_verified: true });
		refused(r);
		assert.match(false, userinfo_fetched(r), "UserInfo is only fetched when the ID token has no email");
	});

	it('UserInfo: an email verified in the UserInfo response matches its role', () => {
		let r = login({ email: null, email_verified: null }, { email: "admin@example.com", email_verified: true });
		assert.match(true, userinfo_fetched(r));
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:admin", r.username);
	});

	it('UserInfo: an unverified or unflagged UserInfo email, or the string "true", is refused, with a warning', () => {
		for (let v in [ false, "true", null ]) {
			let ui = { email: "admin@example.com" };
			if (v != null) ui.email_verified = v;
			let r = login({ email: null, email_verified: null }, ui);
			assert.match(true, userinfo_fetched(r));
			refused(r);
			assert.match(1, length(warned(r)), `${v}`);
		}
	});

	it("UserInfo: the ID token's email_verified never vouches for the UserInfo email", () => {
		// The ID token says true but carries no email; UserInfo's email has no flag.
		let r = login({ email: null, email_verified: true }, { email: "admin@example.com" });
		assert.match(true, userinfo_fetched(r));
		refused(r);
	});

	it("UserInfo: the ID token's false does not taint a UserInfo email verified there", () => {
		let r = login({ email: null, email_verified: false }, { email: "admin@example.com", email_verified: true });
		assert.match("sso:admin", r.username);
	});

	it('UserInfo: with require_email_verified off, an unflagged UserInfo email matches as before', () => {
		let r = login({ email: null, email_verified: null }, { email: "admin@example.com" }, { require_email_verified: false });
		assert.match("sso:admin", r.username);
		assert.match(0, length(warned(r)));
	});

	it('oidc_user: a verified email is stored as the session label', () => {
		let r = login({ email: "admin@example.com", email_verified: true });
		assert.match("sso:admin", r.username);
		assert.match("admin@example.com", r.values.oidc_user);
	});

	it('oidc_user: an unverified email is left out, and the user still logs in through a group', () => {
		let r = login({ email: "admin@example.com", email_verified: false, groups: [ "staff" ] });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:staff", r.username);
		assert.match(false, exists(r.values, "oidc_user"), "no label, not even null");
	});

	it('oidc_user: with require_email_verified off, an unverified email matches its role but is left out', () => {
		let r = login({ email: "admin@example.com", email_verified: false }, null, { require_email_verified: false });
		assert.match(contains({ ok: true }), r.result, `${r.result.error}`);
		assert.match("sso:admin", r.username, "the email still matched");
		assert.match(false, exists(r.values, "oidc_user"), "no label, not even null");
	});

	it('oidc_user: an email verified only in UserInfo is stored', () => {
		let r = login({ email: null, email_verified: null }, { email: "admin@example.com", email_verified: true });
		assert.match("admin@example.com", r.values.oidc_user);
	});
});

describe('handshake: split-horizon', () => {
	// Full callback with a pathful issuer behind split-horizon. The ID token
	// carries no email, so UserInfo is fetched too. Every back-channel request
	// must go to the internal origin with the issuer's path intact; the HTTP
	// mock is strict, so a request to any public URL dies.
	function pathful_flow(issuer, internal, paths) {
		// Endpoint paths are absolute on the IdP's origin, as real IdPs publish
		// them: some sit under the issuer path (Keycloak), some do not (Authentik).
		let pub_origin = match(issuer, /^https:\/\/[^\/]+/)[0];
		let int_origin = replace(internal, /\/$/, "");
		let issuer_path = replace(substr(issuer, length(pub_origin)), /\/$/, "");
		let pub  = (p) => pub_origin + p;
		let priv = (p) => int_origin + p;
		let discovery_doc = {
			issuer: issuer,
			authorization_endpoint: pub(paths.auth),
			token_endpoint:         pub(paths.token),
			jwks_uri:               pub(paths.jwks),
			userinfo_endpoint:      pub(paths.userinfo),
			end_session_endpoint:   pub(paths.logout),
		};
		let config = {
			...f.MOCK_CONFIG, issuer_url: issuer, internal_issuer_url: internal, redirect_uri: "https://router/callback",
			roles: [ { name: "admin", emails: ["admin@example.com"] } ]
		};
		let posted = [], result = null, got = null;

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
			http_client: {
				data: {
					[priv(issuer_path + "/.well-known/openid-configuration")]: { status: 200, body: discovery_doc },
					[priv(paths.jwks)]:     { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[priv(paths.userinfo)]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "admin@example.com", email_verified: true } },
				},
				behavior: {
					post: (url, opts) => {
						push(posted, url);
						if (url != priv(paths.token)) return { ok: true, data: { status: 404, body: "wrong token URL" } };
						let access_token = "at-pathful";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let claims = { ...f.MOCK_CLAIMS, iss: issuer, nonce: "test-nonce", at_hash };
						delete claims.email;
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(claims, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let hs = session.create_state(deps, 0).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			result = handshake.authenticate(deps, config, { query: { code: "c1", state: raw.state }, cookies: { "__Host-luci_sso_state": hs.token } });
			got = map(spy(deps.http).calls.get || [], (c) => c[0]);
		});
		return { result, posted, got, priv };
	}

	it('Keycloak-style issuer (/realms/home): token, JWKS and UserInfo go to the internal origin with the path', () => {
		let r = pathful_flow("https://kc.example.com/realms/home", "https://10.0.0.5:8443", {
			auth:     "/realms/home/protocol/openid-connect/auth",
			token:    "/realms/home/protocol/openid-connect/token",
			jwks:     "/realms/home/protocol/openid-connect/certs",
			userinfo: "/realms/home/protocol/openid-connect/userinfo",
			logout:   "/realms/home/protocol/openid-connect/logout",
		});
		assert.match(contains({ ok: true, data: contains({ email: "admin@example.com" }) }), r.result, `${r.result.error} ${r.result.details}`);
		assert.match([ "https://10.0.0.5:8443/realms/home/protocol/openid-connect/token" ], r.posted);
		assert.match(true, index(r.got, "https://10.0.0.5:8443/realms/home/protocol/openid-connect/certs") >= 0, 'JWKS via internal origin');
		assert.match(true, index(r.got, "https://10.0.0.5:8443/realms/home/protocol/openid-connect/userinfo") >= 0, 'UserInfo via internal origin');
	});

	it('Authentik-style issuer (/application/o/luci/): the same, with a trailing slash', () => {
		let r = pathful_flow("https://auth.example.com/application/o/luci/", "https://10.0.0.6/", {
			auth: "/application/o/authorize/", token: "/application/o/token/",
			jwks: "/application/o/luci/jwks/", userinfo: "/application/o/userinfo/",
			logout: "/application/o/luci/end-session/",
		});
		assert.match(contains({ ok: true }), r.result, `${r.result.error} ${r.result.details}`);
		assert.match([ "https://10.0.0.6/application/o/token/" ], r.posted);
		assert.match(true, index(r.got, "https://10.0.0.6/application/o/luci/.well-known/openid-configuration") >= 0, 'discovery under the issuer path');
		assert.match(true, index(r.got, "https://10.0.0.6/application/o/luci/jwks/") >= 0, 'JWKS via internal origin');
		assert.match(true, index(r.got, "https://10.0.0.6/application/o/userinfo/") >= 0, 'UserInfo via internal origin');
	});

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
				{ name: "admin", emails: ["admin@example.com"] }
			]
		};

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
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
			let s_res = session.create_state(deps, 0);
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
			roles: [ { name: "admin", emails: ["admin@example.com"] } ]
		};

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s456" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
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
			let s_res = session.create_state(deps, 0);
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
		// issuer_url must be the declared issuer exactly, slash included.
		let issuer_url = "https://idp.com/";
		let internal_issuer_url = "https://internal.lan";

		let discovery_doc = {
			issuer: "https://idp.com/",
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
			fs:    { data: {} },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[internal_issuer_url + "/token"]: { status: 200, body: { access_token: "at", id_token: "it" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps, 0);
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
			roles: [{ name: "admin", emails: ["user-123"] }]
		};

		let log_calls = [];
		let nonce_ref = null;

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
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
			roles: [{ name: "admin", emails: ["user-123"] }]
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
				fs:    { data: {} },
				ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
				uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
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

	it('at the handshake cap, a new login gets 503 and pending logins survive', () => {
		// Every slot holds a live handshake (created just now). A flood must not
		// evict them: the new login is refused, and each pending one still verifies.
		let config = base_config();
		with_context({
			// The mock's own stat reports mtime 0, which reap treats as unknown and
			// skips. Report every handshake as created now, so an eviction bug
			// (deleting live handshakes) would actually delete them.
			fs: { data: {}, behavior: { stat: (p) => ({ mtime: 1516239022 }) } },
			http_client: { data: { [config.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY } } },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let first = null;
			for (let i = 0; i < common.LIMIT_PENDING_HANDSHAKES; i++) {
				let res = session.create_state(deps, config.clock_tolerance);
				assert.match(truthy(), res.ok, `Failed to create handshake #${i}: ${res.error}`);
				if (i == 0) first = res.data;
			}

			let res = handshake.initiate(deps, config);
			assert.match(contains({ ok: false, error: 'HANDSHAKE_CAPACITY_EXCEEDED' }), res);
			assert.match(503, res.details.http_status);
			assert.match(contains({ ok: true }), session.verify_state(deps, first.token, first.state, config.clock_tolerance),
				'the oldest pending login is still usable');
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
			roles: [{ name: "admin", emails: ["user-123"] }]
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

			let auth_res = handshake.authenticate(deps, test_config, request);
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
			roles: [ { name: "admin", groups: ["idp-admin"], emails: ["user@example.com"] } ]
		};
		let nonce_ref = null;

		with_context({
			fs:    { data: {} },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			uci:   { data: rpcd_logins({ admin: { read: ["*"], write: ["*"] } }) },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]:          { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com", email_verified: true, groups: groups } }
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
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
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
