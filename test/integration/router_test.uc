import { assert, assert_eq, when, and, then } from 'testing';
import * as router from 'luci_sso.router';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";

function create_mock_io() {
	return {
		_responses: {},
		_now: 1516239022 + 10,
		_files: { "/etc/luci-sso/secret.key": TEST_SECRET },
		_ubus_logins: [],
		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; },
		rename: function(old, new) { this._files[new] = this._files[old]; delete this._files[old]; return true; },
		http_get: function(url) { 
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		},
		http_post: function(url, opts) {
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		},
		log: function(level, msg) { /* ignore in final run */ },
		ubus_call: function(obj, method, args) {
			if (obj == "session" && method == "login") {
				push(this._ubus_logins, args);
				return { ubus_rpc_session: `session-for-${args.username}` };
			}
			return {};
		}
	};
}

/**
 * Standard configuration used for most tests.
 * Matches claims in fixtures.POLICY.JWT_WITH_CLAIMS
 */
const MOCK_CONFIG = {
	issuer_url: "https://idp.com",
    internal_issuer_url: "https://idp.com",
	client_id: "my-app",
	client_secret: "secret123",
	redirect_uri: "http://router/callback",
	alg: "RS256",
	now: 1516239022 + 10,
	user_mappings: [
		{ rpcd_user: "system_admin", rpcd_password: "p1", emails: ["1234567890"] }
	]
};

const RS256_JWK = fixtures.POLICY.CLAIMS_JWK;

/**
 * Setup helper for discovery mock
 */
function mock_discovery(io, issuer) {
	io._responses[issuer + "/.well-known/openid-configuration"] = {
		status: 200,
		body: { 
			issuer: issuer, 
			authorization_endpoint: issuer + "/auth",
			token_endpoint: issuer + "/token",
			jwks_uri: issuer + "/jwks"
		}
	};
}

// =============================================================================
// Specifications
// =============================================================================

when("initiating the OIDC login flow", () => {
	let io = create_mock_io();
	
	and("the Identity Provider returns a massive response that exceeds memory limits", () => {
		io._responses["https://idp.com/.well-known/openid-configuration"] = { error: "RESPONSE_TOO_LARGE" };
		let res = router.handle(io, MOCK_CONFIG, { path: "/" });
		then("it should fail discovery and return a 500 Internal Error", () => {
			assert_eq(res.status, 500);
		});
	});

	and("the Identity Provider is discoverable and healthy", () => {
		mock_discovery(io, "https://idp.com");
		let res = router.handle(io, MOCK_CONFIG, { path: "/" });
		then("it should return a 302 redirect to the Identity Provider", () => {
			assert_eq(res.status, 302);
			assert(index(res.headers[0], "Location: https://idp.com/auth") == 0);
		});
	});
});

when("processing the OIDC callback", () => {
	
	and("a valid user returns from the IdP with an honest token", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: fixtures.POLICY.JWT_WITH_CLAIMS } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should verify all claims, create a LuCI session, and redirect to the dashboard", () => {
			assert_eq(res.status, 302);
			assert_eq(res.headers[0], "Location: /cgi-bin/luci/");
			assert_eq(io._ubus_logins[0].username, "system_admin");
		});
	});

	and("an attacker uses a valid token issued for a DIFFERENT application (Imposter Client)", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { id_token: fixtures.POLICY.JWT_WITH_CLAIMS } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		
		let bad_config = { ...MOCK_CONFIG, client_id: "someone-elses-app" };
		let res = router.handle(io, bad_config, req);

		then("it should detect the audience mismatch and reject the login", () => {
			assert_eq(res.status, 401);
		});
	});

	and("a valid token is presented but it was issued by an UNTRUSTED server (Rogue Issuer)", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { id_token: fixtures.POLICY.JWT_WITH_CLAIMS } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		
		let rogue_config = { ...MOCK_CONFIG, issuer_url: "https://trust-only-me.com", internal_issuer_url: "https://idp.com" };
		let res = router.handle(io, rogue_config, req);

		then("it should detect the issuer mismatch and reject the login", () => {
			assert_eq(res.status, 401);
		});
	});

	and("the Identity Provider goes offline during the handshake (Network Outage)", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 503, body: "Service Unavailable" };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should return a clean 500 Internal Error instead of crashing", () => {
			assert_eq(res.status, 500);
		});
	});

	and("the Identity Provider returns an explicit error (e.g. user cancelled)", () => {
		let io = create_mock_io();
		let req = {
			path: "/callback",
			query_string: "error=access_denied&error_description=User+cancelled"
		};
		
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should show the error to the user and return a 400 Bad Request", () => {
			assert_eq(res.status, 400);
		});
	});

	and("the user has waited too long and the handshake has expired", () => {
		let io = create_mock_io();
		let handshake = session.create_state(io).data;
		io._now += 600;

		let req = {
			path: "/callback",
			query_string: `code=c&state=${handshake.state}`,
			http_cookie: `luci_sso_state=${handshake.token}`
		};
		
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should reject the login with a 401 Unauthorized", () => {
			assert_eq(res.status, 401);
		});
	});

	and("the user is authenticated at the IdP but not authorized in our whitelist", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: fixtures.POLICY.JWT_WITH_CLAIMS } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		
		let bad_config = { ...MOCK_CONFIG, user_mappings: [] };
		let res = router.handle(io, bad_config, req);

		then("it should deny access with a 403 Forbidden", () => {
			assert_eq(res.status, 403);
		});
	});
});

when("a user requests to logout", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, { path: "/logout" });

	then("it should clear the LuCI session cookies", () => {
		assert(index(res.headers[1], "sysauth_https=;") >= 0);
		assert(index(res.headers[2], "sysauth=;") >= 0);
	});

	then("it should redirect back to the landing page", () => {
		assert_eq(res.headers[0], "Location: /");
	});
});

when("accessing an unhandled system path", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, { path: "/unknown/path" });

	then("it should return a 404 Not Found error", () => {
		assert_eq(res.status, 404);
	});
});