import { assert, assert_eq, when, and, then } from 'testing';
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
// Tier 3: Behavioral Integration (Platinum Refactor)
// =============================================================================

when("initiating the OIDC login flow", () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });

	and("the Identity Provider returns a massive response that exceeds memory limits", () => {
		factory.with_responses({ "https://idp.com/.well-known/openid-configuration": { error: "RESPONSE_TOO_LARGE" } }, (io) => {
			let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
			then("it should fail discovery and return a 500 Internal Error", () => {
				assert_eq(res.status, 500);
				assert(res.is_error);
			});
		});
	});

	and("the Identity Provider is discoverable and healthy", () => {
		let responses = { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } };
		factory.with_responses(responses, (io) => {
			let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
			then("it should return a 302 redirect to the Identity Provider", () => {
				assert_eq(res.status, 302);
				assert(index(res.headers["Location"], "https://idp.com/auth") == 0);
			});
		});
	});
});

when("the system is accessed for the first time (Bootstrap)", () => {
	let factory = mock.create(); // NO secret.key exists

	then("it should automatically generate a secret key during the first login attempt", () => {
		let responses = { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } };
		
		let final_key = factory.with_responses(responses, (io) => {
			router.handle(io, MOCK_CONFIG, mock_request("/"));
			return io.read_file("/etc/luci-sso/secret.key");
		});

		assert(final_key, "Secret key should exist after bootstrap");
		assert_eq(length(final_key), 32, "Secret key should be 32 bytes");
	});
});

when("processing the OIDC callback", () => {
	let factory = mock.create().with_files({ "/etc/luci-sso/secret.key": TEST_SECRET });

	and("a valid user returns from the IdP with an honest token", () => {
		factory.with_env({}, (io) => {
			let state_res = session.create_state(io);
			let handshake = state_res.data;
			let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce);

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

			then("it should have performed a UBUS login for the mapped user", () => {
				assert(data.called("ubus", "session", "login"), "Should have called ubus login");
				// Verify tokens were stored
				let found_set = false;
				for (let entry in data.all()) {
					if (entry.type == "ubus" && entry.args[1] == "set") {
						if (entry.args[2].values.oidc_access_token == "at" &&
						    entry.args[2].values.oidc_refresh_token == "rt") {
							found_set = true;
							break;
						}
					}
				}
				assert(found_set, "Access and Refresh tokens must be persisted in UBUS session");
			});
		});
	});

	and("the JWKS cache is stale (IdP rotated keys)", () => {
		factory.with_env({}, (io) => {
			let state_res = session.create_state(io);
			let handshake = state_res.data;
			let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce);

			let cache_path = "/var/run/luci-sso/oidc-jwks-wv5enLcGYIn8PiwhdkeXzhVPct86Lf3q.json";
			let stale_jwks = { keys: [ { kid: "anchor-key", kty: "oct", k: "d3Jvbmc" } ], cached_at: io.time() };

			factory.using(io).with_files({ [cache_path]: sprintf("%J", stale_jwks) }, (io_stale) => {
				let data = factory.using(io_stale)
					.with_responses({
						"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
						"https://idp.com/token": { status: 200, body: { access_token: "at", id_token: id_token } },
						"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
					})
					.with_ubus({ "session:login": (args) => ({ ubus_rpc_session: "session-for-" + args.username }) })
					.spy((spying_io) => {
						let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
						let res = router.handle(spying_io, MOCK_CONFIG, req);
						assert_eq(res.status, 302);
					});

				then("it should have forced a JWKS refresh and eventually succeeded", () => {
					assert(data.called("write_file", cache_path), "Should have updated the cache file");
				});
			});
		});
	});

	and("the user is authenticated at the IdP but NOT found in our local whitelist", () => {
		factory.with_env({}, (io) => {
			let state_res = session.create_state(io);
			let handshake = state_res.data;
			let id_token = f.sign_anchor_token(crypto, "https://idp.com", "unknown", io.time(), handshake.nonce);

			factory.using(io).with_responses({
				"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
				"https://idp.com/token": { status: 200, body: { access_token: "at", id_token: id_token } },
				"https://idp.com/jwks": { status: 200, body: { keys: [ f.ANCHOR_JWK ] } }
			}, (io_http) => {
				let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
				let res = router.handle(io_http, { ...MOCK_CONFIG, user_mappings: [] }, req);
				then("it should return Forbidden for non-whitelisted user", () => {
					assert_eq(res.status, 403);
					assert_eq(res.code, "USER_NOT_AUTHORIZED");
				});
			});
		});
	});

	and("an attacker attempts to replay a valid state token", () => {
		factory.with_env({}, (io) => {
			let state_res = session.create_state(io);
			let handshake = state_res.data;
			let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });

			let factory_with_responses = factory.using(io).with_responses({
				"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC },
				"https://idp.com/token": { error: "STOP_HERE" } 
			});
			
			factory_with_responses.with_env({}, (io_exec) => {
				router.handle(io_exec, MOCK_CONFIG, req);
			});

			factory_with_responses.with_env({}, (io_exec) => {
				let res = router.handle(io_exec, MOCK_CONFIG, req);
				then("it should reject the replay with a 401 Unauthorized", () => {
					assert_eq(res.status, 401);
					assert_eq(res.code, "STATE_NOT_FOUND");
				});
			});
		});
	});

	and("an attacker sends binary garbage or malformed protocol parameters", () => {
		let responses = { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } };
		factory.with_responses(responses, (io) => {
			let req = mock_request("/callback", { state: "s" }, { luci_sso_state: "!!!" });
			let res = router.handle(io, MOCK_CONFIG, req);

			then("it should fail safely with an error and not crash", () => {
				assert(res.status >= 400);
				assert(res.is_error);
			});
		});
	});
});

when("a user requests to logout", () => {
	let factory = mock.create().with_ubus({ "session:destroy": {} });

	let data = factory.spy((io) => {
		let req = mock_request("/logout", {}, { "sysauth": "session-12345" });
		let res = router.handle(io, MOCK_CONFIG, req);
		assert_eq(res.status, 302);
		assert_eq(res.headers["Location"], "/");
	});

	then("it should destroy the UBUS session on the server side", () => {
		assert(data.called("ubus", "session", "destroy"));
	});
});

when("accessing an unhandled system path", () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = router.handle(io, MOCK_CONFIG, mock_request("/unknown/path"));
		then("it should return a 404 Not Found error", () => {
			assert_eq(res.status, 404);
		});
	});
});