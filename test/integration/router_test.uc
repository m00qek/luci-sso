import { describe, it, assert, truthy, falsy, spy } from 'utest';
import * as router from 'luci_sso.router';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as session from 'luci_sso.session';
import * as common from 'luci_sso.session.common';
import * as ratelimit from 'luci_sso.ratelimit';
import * as netaddr from 'luci_sso.netaddr';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as config_loader from 'luci_sso.config';
import * as web_mod from 'luci_sso.web';
import { with_context, rpcd_logins, UBUS_NO_DATA } from 'context';
import * as tf from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Integration bucket — enter at router.handle(deps, config, request) with
// a full deps graph built by with_context (real module subgraph, faked system
// boundary). Covers dispatch, login/callback, rate-limit, security, and error
// mapping. The logout flow lives in logout_test.uc.

const MOCK_CONFIG = {
	...tf.MOCK_CONFIG,
	issuer_url: "https://idp.com",
	internal_issuer_url: "https://idp.com",
	redirect_uri: "https://router/callback",
	roles: [
		{ name: "system_admin", emails: ["user-123"] }
	]
};

const MOCK_DISC_DOC = {
	...tf.MOCK_DISCOVERY,
	issuer: "https://idp.com",
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint: "https://idp.com/token",
	jwks_uri: "https://idp.com/jwks"
};

function mock_request(path, query, cookies, env) {
	return {
		path: path || "/",
		query: query || {},
		cookies: cookies || {},
		env: env || {}
	};
}

describe('router: login', () => {
	it('handle massive discovery response', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { error: "RESPONSE_TOO_LARGE" } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/"));
			assert.match(falsy(), res.ok, "Should fail on discovery failure");
			assert.match(502, res.details.http_status, "An IdP back-channel failure is a 502");
		});
	});

	it('redirect to healthy IdP', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/"));
			assert.match(truthy(), res.ok, "Router handle should succeed");
			assert.match(302, res.data.status);
			assert.match(0, index(res.data.headers["Location"], "https://idp.com/auth"), "Redirect MUST point to auth endpoint");
		});
	});
});

describe('router: enabled', () => {
	it('returns JSON response', () => {
		let request = mock_request("/", { action: "enabled" });

		with_context({
			uci: { data: { "luci-sso": { "default": { ".type": "oidc", enabled: "1" } } } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, request);
			assert.match(truthy(), res.ok);
			assert.match(200, res.data.status);
			assert.match('{"enabled": true}', res.data.body);
			assert.match("application/json", res.data.headers["Content-Type"]);
		});

		with_context({
			uci: { data: { "luci-sso": { "default": { ".type": "oidc", enabled: "0" } } } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, request);
			assert.match(truthy(), res.ok);
			assert.match('{"enabled": false}', res.data.body);
		});
	});
});

describe('router: callback', () => {
	it('successful authentication and UBUS login', () => {
		let ubus_create_called = false;
		let found_set = false;
		let at = "mock-access-token-123456";
		let pending_id_token = null;

		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, refresh_token: "rt", id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			uci: { data: rpcd_logins({ system_admin: { read: ["*"], write: ["*"] } }) },
			ubus: {
				data: {
					"session:create": (args) => { ubus_create_called = true; return { ubus_rpc_session: "session-for-root" }; },
					"session:grant": UBUS_NO_DATA,
					"session:set": (args) => {
						if (args && args.values && args.values.oidc_access_token == at) found_set = true;
						return UBUS_NO_DATA;
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			let payload = { ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash };
			pending_id_token = h.generate_id_token(payload, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req);
			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match("/cgi-bin/luci/", res.data.headers["Location"]);
		});

		assert.match(truthy(), ubus_create_called, "Should have called ubus create");
		assert.match(truthy(), found_set, "Tokens must be persisted in UBUS session");
	});

	it('handle stale JWKS cache recovery', () => {
		let at = "mock-at";
		let cache_path = "/var/run/luci-sso/oidc-jwks-wv5enLcGYIn8PiwhdkeXzhVPct86Lf3q.json";
		let pending_id_token = null;

		with_context({
			fs: {
				data: {
					[cache_path]: sprintf("%J", { keys: [ tf.MOCK_JWK ], cached_at: 1516239022 })
				}
			},
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.ROTATION_NEW_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			uci: { data: rpcd_logins({ system_admin: { read: ["*"], write: ["*"] } }) },
			ubus: {
				data: {
					"session:create": (args) => ({ ubus_rpc_session: "s" }),
					"session:grant": UBUS_NO_DATA,
					"session:set": UBUS_NO_DATA
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			let payload = { ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash };
			pending_id_token = h.generate_id_token(payload, tf.ROTATION_NEW_PRIVKEY, "RS256", tf.ROTATION_NEW_JWK.kid);

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			router.handle(deps, MOCK_CONFIG, req);

			let rename_calls = spy(deps.fs).calls.rename;
			assert.match(truthy(), length(rename_calls) > 0, "Should have used atomic rename for cache update");

			let cache_content = deps.fs.readfile(cache_path);
			let cache_res = encoding.safe_json(cache_content);
			assert.match(truthy(), cache_res.ok, "Cache should be valid JSON");
			assert.match(tf.ROTATION_NEW_JWK.kid, cache_res.data.keys[0].kid, "JWKS keys should be updated");
			assert.match(truthy(), cache_res.data.cached_at >= 1516239022, "Cache timestamp should be updated");
		});
	});

	it('reject non-whitelisted users', () => {
		let at = "mock-at";
		let pending_id_token = null;

		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			pending_id_token = h.generate_id_token({ ...tf.MOCK_CLAIMS, iss: "https://idp.com", sub: "unknown", email: "unknown@example.com", nonce: handshake_data.nonce, at_hash: at_hash }, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, { ...MOCK_CONFIG, roles: [] }, req);
			assert.match(falsy(), res.ok);
			assert.match(403, res.details.http_status, "Should return Forbidden for non-whitelisted user");
			assert.match("USER_NOT_AUTHORIZED", res.error);
		});
	});

	it('reject token replay', () => {
		let access_token = "ALREADY_USED";
		let res_h = crypto.hash_sha256_hex(native, access_token);
		assert.match(truthy(), Result.is(res_h));
		let token_id = res_h.data;
		let preregistered = `/var/run/luci-sso/tokens/${token_id}`;
		let pending_id_token = null;

		with_context({
			fs: {
				data: {},
				behavior: {
					mkdir: (path, mode) => {
						if (path == preregistered) return false;
						return true;
					}
				}
			},
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: access_token, id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
			pending_id_token = h.generate_id_token({ ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash }, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req);
			assert.match(falsy(), res.ok);
			assert.match(403, res.details.http_status);
			assert.match("TOKEN_REPLAYED", res.error);
		});
	});

	it('reject state replay', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });

			router.handle(deps, MOCK_CONFIG, req);

			let res = router.handle(deps, MOCK_CONFIG, req);
			assert.match(falsy(), res.ok);
			assert.match(401, res.details.http_status);
			assert.match("STATE_NOT_FOUND", res.error);
		});
	});

	it('reject code replay', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "REPLAYED_CODE", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req);
			assert.match(falsy(), res.ok);
			assert.match("OIDC_INVALID_GRANT", res.error);
			assert.match(502, res.details.http_status);
		});
	});
});

describe('router: security', () => {
	it('reject PKCE bypass', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant", sub_error: "pkce_mismatch" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "VALID_CODE", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req);
			assert.match(falsy(), res.ok);
			assert.match("OIDC_INVALID_GRANT", res.error);
			assert.match(502, res.details.http_status);
		});
	});

	it('skip token registration on verification failure', () => {
		with_context({
			fs: { data: {} },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 200, body: { access_token: "DO_NOT_REGISTER_ME", id_token: "invalid.jwt.sig" } },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res1 = router.handle(deps, MOCK_CONFIG, req);
			assert.match(falsy(), res1.ok, "Should fail verification");
			assert.match(401, res1.details.http_status);

			let state_res2 = session.create_state(deps, 0);
			assert.match(truthy(), Result.is(state_res2));
			let handshake_data2 = state_res2.data;
			let req2 = mock_request("/callback", { code: "c2", state: handshake_data2.state }, { "__Host-luci_sso_state": handshake_data2.token });
			let res2 = router.handle(deps, MOCK_CONFIG, req2);

			assert.match(falsy(), res2.ok);
			assert.match(401, res2.details.http_status, "Should fail verification again (NOT replay) because token wasn't registered");
			assert.match(truthy(), res2.error != "TOKEN_REPLAYED", "Should NOT fail with replay error");
		});
	});
});

describe('router: routing', () => {
	it('handle unhandled system path', () => {
		with_context({
			fs: { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/unknown/path"));
			assert.match(falsy(), res.ok);
			assert.match(404, res.details.http_status);
		});
	});
});

// ─── return_to (issue #27) ───────────────────────────────────────────────────

// A whole login through router.handle: GET / with the given query, then the
// callback with the state and cookie it handed out. `tamper`, when given, may
// change the stored handshake before the callback, as an edit of the file on
// disk would. Returns the initiation and callback responses, the stored
// handshake (before tampering) and the log lines.
function login_round_trip(query, tamper) {
	let at = "mock-access-token-return-to";
	let pending_id_token = null;
	let out = { logs: [] };

	with_context({
		fs: { data: {} },
		http_client: {
			data: {
				"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
				"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
			},
			behavior: {
				post: (url, opts) => {
					if (url == "https://idp.com/token")
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, id_token: pending_id_token }) } };
					return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
				}
			}
		},
		uci: { data: rpcd_logins({ system_admin: { read: ["*"], write: ["*"] } }) },
		ubus: {
			data: {
				"session:create": (args) => ({ ubus_rpc_session: "session-return-to" }),
				"session:grant": UBUS_NO_DATA,
				"session:set": UBUS_NO_DATA
			}
		},
		clock: { data: { now: 1516239022 } }
	}, (deps) => {
		deps.log = (level, msg) => push(out.logs, `${level}: ${msg}`);

		let start = router.handle(deps, MOCK_CONFIG, mock_request("/", query));
		assert.match(truthy(), start.ok, "the login starts");
		out.start = start.data;

		let state = match(start.data.headers["Location"], /[?&]state=([A-Za-z0-9_-]+)/)[1];
		let token = match(start.data.headers["Set-Cookie"], /^__Host-luci_sso_state=([A-Za-z0-9_-]+);/)[1];
		let path = `${common.HANDSHAKE_DIR}/handshake_${token}.json`;
		let stored = json(deps.fs.readfile(path));
		out.stored = { ...stored };
		if (tamper) {
			tamper(stored);
			deps.fs.writefile(path, sprintf("%J", stored));
		}

		let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let payload = { ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: stored.nonce, at_hash: at_hash };
		pending_id_token = h.generate_id_token(payload, tf.MOCK_PRIVKEY, "RS256");

		let res = router.handle(deps, MOCK_CONFIG, mock_request("/callback", { code: "c", state: state }, { "__Host-luci_sso_state": token }));
		assert.match(truthy(), res.ok, "the callback succeeds");
		out.callback = res.data;
	});

	return out;
}

function logged(out, pattern) {
	return length(filter(out.logs, (l) => match(l, pattern))) > 0;
}

describe('router: return_to — the requested page', () => {
	it('returns to the page the login started from', () => {
		let page = "/cgi-bin/luci/admin/services/sso";
		let out = login_round_trip({ return_to: page });
		assert.match(302, out.callback.status);
		assert.match(page, out.callback.headers["Location"]);
		assert.match(page, out.stored.return_to, "kept in the handshake on the router");
	});

	it('keeps the query string of the page', () => {
		let page = "/cgi-bin/luci/admin/system/package-manager?query=luci&page=2";
		let out = login_round_trip({ return_to: page });
		assert.match(page, out.callback.headers["Location"]);
	});

	it('never sends return_to to the IdP or puts it in a cookie', () => {
		let out = login_round_trip({ return_to: "/cgi-bin/luci/admin/services/sso" });
		assert.match(-1, index(out.start.headers["Location"], "return_to"));
		assert.match(-1, index(out.start.headers["Location"], "services"));
		assert.match(-1, index(out.start.headers["Set-Cookie"], "services"));
		for (let c in out.callback.headers["Set-Cookie"])
			assert.match(-1, index(c, "services"));
	});

	it('without return_to, the callback still lands on /cgi-bin/luci/ and logs nothing about it', () => {
		let out = login_round_trip({});
		assert.match("/cgi-bin/luci/", out.callback.headers["Location"]);
		assert.match(false, exists(out.stored, "return_to"));
		assert.match(false, logged(out, /return_to/));
	});
});

describe('router: return_to — hostile values', () => {
	for (let hostile in [
		"https://evil.example/",
		"//evil.example/",
		"/\\evil.example",
		"/cgi-bin/luci//evil.example",
		"/cgi-bin/luci/../../evil",
		"/cgi-bin/luci/%2e%2e/%2e%2e/",
		"/cgi-bin/luci/\r\nSet-Cookie:x",
		"/cgi-bin/luci-sso/logout",
		"javascript:alert(1)",
	]) {
		let value = hostile;
		it(`drops ${encoding.log_safe(value)} at the start and lands on /cgi-bin/luci/`, () => {
			let out = login_round_trip({ return_to: value });
			assert.match(false, exists(out.stored, "return_to"), "nothing is stored");
			assert.match("/cgi-bin/luci/", out.callback.headers["Location"]);
			assert.match(truthy(), logged(out, /^info: Ignoring return_to /));
		});
	}

	it('falls back to /cgi-bin/luci/ when the stored page was edited to another site', () => {
		let out = login_round_trip({ return_to: "/cgi-bin/luci/admin/services/sso" }, (hs) => {
			hs.return_to = "//evil.example/";
		});
		assert.match("/cgi-bin/luci/", out.callback.headers["Location"]);
		assert.match(truthy(), logged(out, /^warn: Stored return_to refused: not a LuCI page; returning to LuCI's start page \[session_id: /));
	});

	it('falls back to /cgi-bin/luci/ when the stored page is not a string', () => {
		let out = login_round_trip({ return_to: "/cgi-bin/luci/admin/services/sso" }, (hs) => {
			hs.return_to = { href: "https://evil.example/" };
		});
		assert.match("/cgi-bin/luci/", out.callback.headers["Location"]);
		assert.match(truthy(), logged(out, /^warn: Stored return_to refused: not a string/));
	});

	it('falls back to /cgi-bin/luci/ when a page was planted in a handshake that had none', () => {
		let out = login_round_trip({}, (hs) => {
			hs.return_to = "https://evil.example/";
		});
		assert.match("/cgi-bin/luci/", out.callback.headers["Location"]);
	});
});

// ─── folded reproduction cases (← tier2 router_*, cgi_error, dos_ratelimit) ────

describe('router: enabled action (reproduction)', () => {
	it('enabled endpoint returns JSON even if disabled (W2)', () => {
		let mock_uci = {
			"luci-sso": {
				"default": { ".type": "oidc", "enabled": "0" }
			}
		};

		with_context({
			fs:    { data: {} },
			uci:   { data: mock_uci },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let getenv = (k) => {
				let env = { PATH_INFO: "/", QUERY_STRING: "action=enabled", HTTP_HOST: "luci.test" };
				return env[k] || null;
			};

			let res_req = web_mod.request({ getenv });
			assert.match(truthy(), res_req.ok);
			let req = res_req.data;

			let res_c = config_loader.load({ uci: deps.uci, log: deps.log });
			assert.match(falsy(), res_c.ok);
			assert.match("SSO_DISABLED", res_c.error);

			let res_router = router.handle(deps, null, req);
			assert.match(truthy(), res_router.ok, "Action 'enabled' MUST succeed even without config");
			assert.match(200, res_router.data.status);
			assert.match('{"enabled": false}', res_router.data.body);
		});
	});
});

describe('router: null config guard (reproduction)', () => {
	it('null config guard (B2)', () => {
		with_context({
			fs:    { data: {} },
			uci:   { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/", query: {}, cookies: {}, headers: {} };
			let res = router.handle(deps, null, req);
			assert.match(falsy(), res.ok, "Should fail when config is null");
			assert.match("SSO_DISABLED", res.error);
			assert.match(500, res.details.http_status, "the same status entry.uc renders for disabled SSO");
		});
	});
});

describe('router: per-client rate limiting', () => {
	const DISC = { [tf.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: tf.MOCK_DISCOVERY } };
	const login = (addr) => ({ path: "/", query: {}, cookies: {}, client: addr });

	it('limits one client\'s login initiations and leaves other clients alone', () => {
		let test_config = { ...tf.MOCK_CONFIG, enabled: "1" };
		with_context({ fs: { data: {} }, http_client: { data: DISC }, clock: { data: { now: 1516239022 } } }, (deps) => {
			for (let i = 1; i <= 10; i++)
				assert.match(truthy(), router.handle(deps, test_config, login("198.51.100.9")).ok, `initiation ${i}`);

			let res = router.handle(deps, test_config, login("198.51.100.9"));
			assert.match("TOO_MANY_REQUESTS", res.error);
			assert.match(429, res.details.http_status);
			assert.match(truthy(), res.details.retry_after > 0, "tells the client when to retry");

			assert.match(truthy(), router.handle(deps, test_config, login("198.51.100.10")).ok,
				"a different client still gets through");
		});
	});

	it('does not charge callbacks to the login budget', () => {
		let test_config = { ...tf.MOCK_CONFIG, enabled: "1" };
		with_context({ fs: { data: {} }, http_client: { data: DISC }, clock: { data: { now: 1516239022 } } }, (deps) => {
			let cb = { path: "/callback", query: { code: "c", state: "s" }, cookies: {}, client: "198.51.100.9" };
			for (let i = 0; i < 15; i++) router.handle(deps, test_config, cb);
			assert.match(truthy(), router.handle(deps, test_config, login("198.51.100.9")).ok);
		});
	});

	it('exempts action=enabled from every budget (N3)', () => {
		let test_config = { ...tf.MOCK_CONFIG, enabled: "1" };
		with_context({
			fs: { data: {} },
			uci: { data: { "luci-sso": { "default": { ".type": "oidc", "enabled": "1" } } } },
			http_client: { data: DISC },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			for (let i = 0; i < 11; i++) router.handle(deps, test_config, login("198.51.100.9"));
			let probe = { path: "/", query: { action: "enabled" }, cookies: {}, client: "198.51.100.9" };
			for (let i = 0; i < 40; i++) {
				let res = router.handle(deps, test_config, probe);
				assert.match(truthy(), res.ok, "the enabled probe is never rate limited");
				assert.match(200, res.data.status);
			}
		});
	});

	it('treats a request without REMOTE_ADDR as the shared unknown client', () => {
		let test_config = { ...tf.MOCK_CONFIG, enabled: "1" };
		with_context({ fs: { data: {} }, http_client: { data: DISC }, clock: { data: { now: 1516239022 } } }, (deps) => {
			for (let i = 0; i < 10; i++) router.handle(deps, test_config, { path: "/", query: {}, cookies: {} });
			assert.match("TOO_MANY_REQUESTS", router.handle(deps, test_config, login("not-an-address")).error);
		});
	});
});

describe('router: per-client rate limiting — a trusted reverse proxy', () => {
	const NOW = 1516239022;
	const DISC = { [tf.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: tf.MOCK_DISCOVERY } };
	// As config.load gives it: the list, and the list parsed once.
	const TRUSTED = [ "127.0.0.1", "2001:db8:100::/48" ];
	const PROXIED = { ...tf.MOCK_CONFIG, enabled: "1", trusted_proxy: TRUSTED, trusted_ranges: map(TRUSTED, netaddr.parse_cidr) };
	const login = (addr) => ({ path: "/", query: {}, cookies: {}, client: addr });
	const callback = (addr) => ({ path: "/callback", query: { code: "c", state: "s" }, cookies: {}, client: addr });
	const ctx = (fn, fs) => with_context({ fs: fs || { data: {} }, http_client: { data: DISC }, clock: { data: { now: NOW } } }, fn);
	const refused = (res) => !res.ok && res.error == "TOO_MANY_REQUESTS";

	it('never refuses the trusted address with 429, on either budget', () => {
		ctx((deps) => {
			for (let i = 1; i <= 3 * ratelimit.LIMITS.login.requests; i++) {
				let res = router.handle(deps, PROXIED, login("127.0.0.1"));
				assert.match(truthy(), res.ok, `login start ${i}`);
				assert.match(302, res.data.status);
			}
			for (let i = 1; i <= 2 * ratelimit.LIMITS.client.requests; i++)
				assert.match(falsy(), refused(router.handle(deps, PROXIED, callback("127.0.0.1"))), `callback ${i}`);
		});
	});

	it('exempts an address inside a trusted CIDR range', () => {
		ctx((deps) => {
			for (let i = 0; i < 2 * ratelimit.LIMITS.login.requests; i++)
				assert.match(truthy(), router.handle(deps, PROXIED, login(sprintf("2001:db8:100:%x::1", i))).ok, `login start ${i}`);
		});
	});

	it('still limits every other address, as before', () => {
		ctx((deps) => {
			for (let i = 0; i < 3 * ratelimit.LIMITS.login.requests; i++) router.handle(deps, PROXIED, login("127.0.0.1"));
			for (let i = 1; i <= ratelimit.LIMITS.login.requests; i++)
				assert.match(truthy(), router.handle(deps, PROXIED, login("198.51.100.9")).ok, `initiation ${i}`);
			let res = router.handle(deps, PROXIED, login("198.51.100.9"));
			assert.match("TOO_MANY_REQUESTS", res.error, "the 11th from a direct client");
			assert.match(429, res.details.http_status);
			for (let i = 0; i < ratelimit.LIMITS.login.requests; i++) router.handle(deps, PROXIED, login("127.0.0.2"));
			assert.match("TOO_MANY_REQUESTS", router.handle(deps, PROXIED, login("127.0.0.2")).error,
				"a neighbour of the trusted address");
			for (let i = 0; i < ratelimit.LIMITS.login.requests; i++) router.handle(deps, PROXIED, login("2001:db8:101::1"));
			assert.match("TOO_MANY_REQUESTS", router.handle(deps, PROXIED, login("2001:db8:101::1")).error,
				"an address just outside the trusted range");
		});
	});

	it('limits the proxy\'s address like any client when trusted_proxy is empty', () => {
		ctx((deps) => {
			for (let i = 0; i < ratelimit.LIMITS.login.requests; i++)
				assert.match(truthy(), router.handle(deps, tf.MOCK_CONFIG, login("127.0.0.1")).ok);
			assert.match("TOO_MANY_REQUESTS", router.handle(deps, tf.MOCK_CONFIG, login("127.0.0.1")).error);
		});
	});

	it('keeps the global cap on pending handshakes for the trusted address', () => {
		// Every slot holds a live handshake (created just now, as stat reports),
		// so reaping frees nothing. The exempted request still gets 503.
		ctx((deps) => {
			for (let i = 0; i < common.LIMIT_PENDING_HANDSHAKES; i++)
				assert.match(truthy(), session.create_state(deps, PROXIED.clock_tolerance).ok, `handshake ${i}`);
			let res = router.handle(deps, PROXIED, login("127.0.0.1"));
			assert.match("HANDSHAKE_CAPACITY_EXCEEDED", res.error);
			assert.match(503, res.details.http_status);
		}, { data: {}, behavior: { stat: (p) => ({ mtime: NOW }) } });
	});

	it('logs that the address is exempt once, not per request', () => {
		ctx((deps) => {
			let logs = [];
			deps.log = (l, m) => push(logs, [ l, m ]);
			for (let i = 0; i < 20; i++) router.handle(deps, PROXIED, login("127.0.0.1"));
			let notes = filter(logs, (l) => index(l[1], "Request from trusted proxy") == 0);
			assert.match(1, length(notes));
			assert.match("info", notes[0][0]);
			assert.match(0, length(filter(logs, (l) => index(l[1], "rate limit exceeded") >= 0)));
		});
	});
});

describe('router: CGI error rendering (reproduction)', () => {
	it('renders an error response for an unhandled path (W1)', () => {
		let config = {
			enabled: true,
			client_id: "test",
			issuer_url: "https://idp.test",
			redirect_uri: "https://luci.test/callback"
		};

		let stdout_buf = "";
		let stdout = { write: (s) => { stdout_buf += s; }, flush: () => {} };

		let getenv = (k) => {
			let env = { PATH_INFO: "/invalid-path", HTTP_HOST: "luci.test" };
			return env[k] || null;
		};

		with_context({
			fs:    { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let web_deps = { getenv, stdout, log: deps.log };

			let res_req = web_mod.request(web_deps);
			assert.match(truthy(), res_req.ok);
			let req = res_req.data;

			let res_router = router.handle(deps, config, req);
			assert.match(falsy(), res_router.ok, "Router should return error for invalid path");

			let rendered_error = false;
			res_router = router.handle(deps, config, req);
			if (!res_router.ok) {
				let status = (type(res_router.details) == "object") ? res_router.details.http_status : 500;
				web_mod.render_error(web_deps, res_router.error, status);
				rendered_error = true;
			} else {
				web_mod.render(web_deps, res_router.data);
			}

			assert.match(truthy(), rendered_error, "Should have rendered an error response");
		});
	});
});
