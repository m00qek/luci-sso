import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
import * as mock from 'mock';
import * as f from 'integration.fixtures';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";

const MOCK_CONFIG = {
	issuer_url: "https://idp.com",
	internal_issuer_url: "https://idp.com",
	client_id: "luci-app",
	client_secret: "secret123",
	redirect_uri: "http://router/callback",
	alg: "RS256",
	clock_tolerance: 300,
	user_mappings: [
		{ rpcd_user: "system_admin", rpcd_password: "p1", emails: ["1234567890"] }
	]
};

const MOCK_DISC_DOC = { 
	issuer: "https://idp.com", 
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint: "https://idp.com/token",
	jwks_uri: "https://idp.com/jwks"
};

function mock_request(path, query, cookies) {
	return {
		path: path || "/",
		query: query || {},
		cookies: cookies || {}
	};
}

// =============================================================================
// Tier 3: Behavioral Integration (Homogeneous Standard)
// =============================================================================

test('Router: Login Flow - Handle massive discovery response', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_responses({ "https://idp.com/.well-known/openid-configuration": { error: "RESPONSE_TOO_LARGE" } }, (io) => {
		let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
		assert_eq(res.status, 500, "Should return 500 on discovery failure");
		assert(res.is_error);
	});
});

test('Router: Login Flow - Redirect to Healthy IdP', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	let responses = { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } };
	factory.with_responses(responses, (io) => {
		let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
		assert_eq(res.status, 302);
		assert(index(res.headers["Location"], "https://idp.com/auth") == 0, "Redirect MUST point to auth endpoint");
	});
});

test('Router: Bootstrap - Automatic secret key generation', () => {
	let factory = mock.create(); // NO secret.key exists
	let responses = { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } };
	
	let final_key = factory.with_responses(responses, (io) => {
		router.handle(io, MOCK_CONFIG, mock_request("/"));
		return io.read_file("/etc/luci-sso/secret.key");
	});

	assert(final_key, "Secret key should exist after bootstrap");
	assert_eq(length(final_key), 32, "Secret key should be 32 bytes");
});

test('Router: Callback - Successful authentication and UBUS login', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		
		let full_hash = crypto.sha256("at");
		let at_hash = crypto.b64url_encode(substr(full_hash, 0, 16));
		let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce, at_hash);

		let data = factory.using(io)
			.with_responses({
				"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
				"https://idp.com/token": { status: 200, body: { access_token: "at", refresh_token: "rt", id_token: id_token } },
				"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
			})
			.with_ubus({ "session:login": (args) => ({ ubus_rpc_session: "session-for-" + args.username }) })
			.spy((spying_io) => {
				let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
				let res = router.handle(spying_io, MOCK_CONFIG, req);
				assert_eq(res.status, 302);
				assert_eq(res.headers["Location"], "/cgi-bin/luci/");
			});

		assert(data.called("ubus", "session", "login"), "Should have called ubus login");
		let found_set = false;
		for (let entry in data.all()) {
			if (entry.type == "ubus" && entry.args[1] == "set") {
				if (entry.args[2].values.oidc_access_token == "at") found_set = true;
			}
		}
		assert(found_set, "Tokens must be persisted in UBUS session");
	});
});

test('Router: Callback - Handle stale JWKS cache recovery', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let full_hash = crypto.sha256("at");
		let at_hash = crypto.b64url_encode(substr(full_hash, 0, 16));
		let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce, at_hash);

		let cache_path = "/var/run/luci-sso/oidc-jwks-wv5enLcGYIn8PiwhdkeXzhVPct86Lf3q.json";
		let stale_jwks = { keys: [ { kid: "anchor-key", kty: "oct", k: "d3Jvbmc" } ], cached_at: io.time() };

		factory.using(io).with_files({ [cache_path]: sprintf("%J", stale_jwks) }, (io_stale) => {
			let data = factory.using(io_stale)
				.with_responses({
					"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
					"https://idp.com/token": { status: 200, body: { access_token: "at", id_token: id_token } },
					"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
				})
				.with_ubus({ "session:login": (args) => ({ ubus_rpc_session: "s" }) })
				.spy((spying_io) => {
					let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
					router.handle(spying_io, MOCK_CONFIG, req);
				});

			assert(data.called("write_file", cache_path), "Should have updated the cache file");
		});
	});
});

test('Router: Callback - Reject non-whitelisted users', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let full_hash = crypto.sha256("at");
		let at_hash = crypto.b64url_encode(substr(full_hash, 0, 16));
		let id_token = f.sign_anchor_token(crypto, "https://idp.com", "unknown", io.time(), handshake.nonce, at_hash);

		factory.using(io).with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
			"https://idp.com/token": { status: 200, body: { access_token: "at", id_token: id_token } },
			"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
		}, (io_http) => {
			let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
			let res = router.handle(io_http, { ...MOCK_CONFIG, user_mappings: [] }, req);
			assert_eq(res.status, 403, "Should return Forbidden for non-whitelisted user");
			assert_eq(res.code, "USER_NOT_AUTHORIZED");
		});
	});
});

test('Router: Callback - Reject token replay (already used access_token)', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let full_hash = crypto.sha256("ALREADY_USED");
		let at_hash = crypto.b64url_encode(substr(full_hash, 0, 16));
		let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce, at_hash);

		factory.using(io)
			.with_responses({
				"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
				"https://idp.com/token": { status: 200, body: { access_token: "ALREADY_USED", id_token: id_token } },
				"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
			})
			.with_ubus({ "session:list": { "s": { values: { oidc_access_token: "ALREADY_USED" } } } })
			.spy((spying_io) => {
				let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
				let res = router.handle(spying_io, MOCK_CONFIG, req);
				assert_eq(res.status, 403);
				assert_eq(res.code, "TOKEN_REPLAY_DETECTED");
			});
	});
});

test('Router: Callback - Reject state replay (handshake one-time use)', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });

		let factory_with_responses = factory.using(io).with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
			"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } } 
		});
		
		factory_with_responses.with_env({}, (io_exec) => { router.handle(io_exec, MOCK_CONFIG, req); });
		factory_with_responses.with_env({}, (io_exec) => {
			let res = router.handle(io_exec, MOCK_CONFIG, req);
			assert_eq(res.status, 401);
			assert_eq(res.code, "STATE_NOT_FOUND");
		});
	});
});

test('Router: Callback - Reject code replay (IdP level rejection)', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let req = mock_request("/callback", { code: "REPLAYED_CODE", state: handshake.state }, { luci_sso_state: handshake.token });

		factory.using(io).with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
			"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
		}, (io_http) => {
			let res = router.handle(io_http, MOCK_CONFIG, req);
			assert_eq(res.code, "OIDC_INVALID_GRANT");
		});
	});
});

test('Router: Security - Reject PKCE bypass (IdP level rejection)', () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handshake = state_res.data;
		let req = mock_request("/callback", { code: "VALID_CODE", state: handshake.state }, { luci_sso_state: handshake.token });

		factory.using(io).with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
			"https://idp.com/token": { status: 400, body: { error: "invalid_grant", sub_error: "pkce_mismatch" } }
		}, (io_http) => {
			let res = router.handle(io_http, MOCK_CONFIG, req);
			assert_eq(res.code, "OIDC_INVALID_GRANT");
		});
	});
});

test('Router: Logout - Session destruction', () => {
	let factory = mock.create().with_ubus({ "session:destroy": {} });
	let data = factory.spy((io) => {
		let req = mock_request("/logout", {}, { "sysauth": "session-12345" });
		let res = router.handle(io, MOCK_CONFIG, req);
		assert_eq(res.status, 302);
	});
	assert(data.called("ubus", "session", "destroy"));
});

test('Router: Router - Handle unhandled system path', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = router.handle(io, MOCK_CONFIG, mock_request("/unknown/path"));
		assert_eq(res.status, 404);
	});
});
