import { describe, it, assert, truthy, falsy, spy } from 'utest';
import * as router from 'luci_sso.router';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as session from 'luci_sso.session';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';
import * as f from 'tier3.fixtures';
import * as tf from 'tier2.fixtures';
import * as h from 'lib.helpers';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";
const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

const MOCK_CONFIG = {
	...tf.MOCK_CONFIG,
	issuer_url: "https://idp.com",
	internal_issuer_url: "https://idp.com",
	redirect_uri: "https://router/callback",
	roles: [
		{ name: "system_admin", emails: ["user-123"], read: ["*"], write: ["*"] }
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
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { error: "RESPONSE_TOO_LARGE" } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/"), TEST_POLICY);
			assert.match(falsy(), res.ok, "Should fail on discovery failure");
			assert.match(500, res.details.http_status, "Should return 500 status in details");
		});
	});

	it('redirect to healthy IdP', () => {
		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/"), TEST_POLICY);
			assert.match(truthy(), res.ok, "Router handle should succeed");
			assert.match(302, res.data.status);
			assert.match(0, index(res.data.headers["Location"], "https://idp.com/auth"), "Redirect MUST point to auth endpoint");
		});
	});
});

describe('router: bootstrap', () => {
	it('automatic secret key generation', () => {
		let final_key = null;

		with_context({
			fs: { data: {} },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			router.handle(deps, MOCK_CONFIG, mock_request("/"), TEST_POLICY);
			final_key = deps.fs.readfile("/etc/luci-sso/secret.key");
		});

		assert.match(truthy(), final_key, "Secret key should exist after bootstrap");
		assert.match(32, length(final_key), "Secret key should be 32 bytes");
	});
});

describe('router: enabled', () => {
	it('returns JSON response', () => {
		let request = mock_request("/", { action: "enabled" });

		with_context({
			uci: { data: { "luci-sso": { "default": { ".type": "oidc", enabled: "1" } } } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, request, TEST_POLICY);
			assert.match(truthy(), res.ok);
			assert.match(200, res.data.status);
			assert.match('{"enabled": true}', res.data.body);
			assert.match("application/json", res.data.headers["Content-Type"]);
		});

		with_context({
			uci: { data: { "luci-sso": { "default": { ".type": "oidc", enabled: "0" } } } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, request, TEST_POLICY);
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
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, refresh_token: "rt", id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			ubus: {
				data: {
					"session:create": (args) => { ubus_create_called = true; return { ubus_rpc_session: "session-for-root" }; },
					"session:grant": {},
					"session:set": (args) => {
						if (args && args.values && args.values.oidc_access_token == at) found_set = true;
						return {};
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			let payload = { ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash };
			pending_id_token = h.generate_id_token(payload, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
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
					"/etc/luci-sso/secret.key": TEST_SECRET,
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
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			ubus: {
				data: {
					"session:create": (args) => ({ ubus_rpc_session: "s" }),
					"session:grant": {},
					"session:set": {}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			let payload = { ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash };
			pending_id_token = h.generate_id_token(payload, tf.ROTATION_NEW_PRIVKEY, "RS256", tf.ROTATION_NEW_JWK.kid);

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

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
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/jwks": { status: 200, body: { keys: [ tf.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == "https://idp.com/token")
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: at, id_token: pending_id_token }) } };
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
			pending_id_token = h.generate_id_token({ ...tf.MOCK_CLAIMS, iss: "https://idp.com", sub: "unknown", email: "unknown@example.com", nonce: handshake_data.nonce, at_hash: at_hash }, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, { ...MOCK_CONFIG, roles: [] }, req, TEST_POLICY);
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
				data: { "/etc/luci-sso/secret.key": TEST_SECRET },
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
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;

			let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
			pending_id_token = h.generate_id_token({ ...tf.MOCK_CLAIMS, iss: "https://idp.com", email: "user-123", nonce: handshake_data.nonce, at_hash: at_hash }, tf.MOCK_PRIVKEY, "RS256");

			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(falsy(), res.ok);
			assert.match(403, res.details.http_status);
			assert.match("TOKEN_REPLAYED", res.error);
		});
	});

	it('reject state replay', () => {
		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });

			router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(falsy(), res.ok);
			assert.match(401, res.details.http_status);
			assert.match("STATE_NOT_FOUND", res.error);
		});
	});

	it('reject code replay', () => {
		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "REPLAYED_CODE", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(falsy(), res.ok);
			assert.match("OIDC_INVALID_GRANT", res.error);
		});
	});
});

describe('router: security', () => {
	it('reject PKCE bypass', () => {
		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 400, body: { error: "invalid_grant", sub_error: "pkce_mismatch" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "VALID_CODE", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(falsy(), res.ok);
			assert.match("OIDC_INVALID_GRANT", res.error);
		});
	});

	it('skip token registration on verification failure', () => {
		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": TEST_SECRET } },
			http_client: {
				data: {
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 200, body: { access_token: "DO_NOT_REGISTER_ME", id_token: "invalid.jwt.sig" } },
					"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res));
			let handshake_data = state_res.data;
			let req = mock_request("/callback", { code: "c", state: handshake_data.state }, { "__Host-luci_sso_state": handshake_data.token });
			let res1 = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(falsy(), res1.ok, "Should fail verification");
			assert.match(401, res1.details.http_status);

			let state_res2 = session.create_state(deps);
			assert.match(truthy(), Result.is(state_res2));
			let handshake_data2 = state_res2.data;
			let req2 = mock_request("/callback", { code: "c2", state: handshake_data2.state }, { "__Host-luci_sso_state": handshake_data2.token });
			let res2 = router.handle(deps, MOCK_CONFIG, req2, TEST_POLICY);

			assert.match(falsy(), res2.ok);
			assert.match(401, res2.details.http_status, "Should fail verification again (NOT replay) because token wasn't registered");
			assert.match(truthy(), res2.error != "TOKEN_REPLAYED", "Should NOT fail with replay error");
		});
	});
});

describe('router: logout', () => {
	it('OIDC RP-initiated logout', () => {
		let ubus_get_called = false;
		let ubus_destroy_called = false;
		let DISC_WITH_LOGOUT = { ...MOCK_DISC_DOC, end_session_endpoint: "https://idp.com/logout" };

		with_context({
			fs: { data: {} },
			ubus: {
				data: {
					"session:get": (args) => { ubus_get_called = true; return { values: { oidc_id_token: "mock-id-token", token: "csrf-123" } }; },
					"session:destroy": (args) => { ubus_destroy_called = true; return {}; }
				}
			},
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: DISC_WITH_LOGOUT } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", { stoken: "csrf-123" }, { "sysauth": "session-12345" }, { HTTP_HOST: "router.lan" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match(0, index(res.data.headers["Location"], "https://idp.com/logout"), "Should redirect to IdP logout");
			assert.match(truthy(), index(res.data.headers["Location"], "id_token_hint=mock-id-token") != -1, "Should include id_token_hint");
			assert.match(truthy(), match(res.data.headers["Location"], /post_logout_redirect_uri=https%3A%2F%2Frouter%2F(&|$)/), "Should include EXACT post_logout_redirect_uri");
		});

		assert.match(truthy(), ubus_get_called, "Should have retrieved session for id_token_hint");
		assert.match(truthy(), ubus_destroy_called, "Should have destroyed local session");
	});

	it('fallback to local logout', () => {
		let ubus_destroy_called = false;

		with_context({
			fs: { data: {} },
			ubus: {
				data: {
					"session:get": (args) => ({ values: { token: "csrf-456" } }),
					"session:destroy": (args) => { ubus_destroy_called = true; return {}; }
				}
			},
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", { stoken: "csrf-456" }, { "sysauth": "session-12345" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match("/", res.data.headers["Location"]);
		});

		assert.match(truthy(), ubus_destroy_called);
	});

	it('prevent unauthenticated redirect', () => {
		let DISC_WITH_LOGOUT = { ...MOCK_DISC_DOC, end_session_endpoint: "https://idp.com/logout" };

		with_context({
			fs: { data: {} },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: DISC_WITH_LOGOUT } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", {}, {}, { HTTP_HOST: "router.lan" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match("/", res.data.headers["Location"], "Should redirect to root for unauthenticated logout");
		});
	});
});

describe('router: routing', () => {
	it('handle unhandled system path', () => {
		with_context({
			fs: { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, MOCK_CONFIG, mock_request("/unknown/path"), TEST_POLICY);
			assert.match(falsy(), res.ok);
			assert.match(404, res.details.http_status);
		});
	});
});
