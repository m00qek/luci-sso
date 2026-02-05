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
			if (obj == "session" && method == "login") return { ubus_rpc_session: "mock-session-id" };
			return {};
		}
	};
}

const MOCK_CONFIG = {
	issuer_url: "https://idp.com",
	client_id: "my-app",
	client_secret: "secret123",
	redirect_uri: "http://router/callback",
	user_mappings: [
		{ 
			rpcd_user: "admin", 
			rpcd_password: "pw", 
			emails: ["1234567890"] 
		}
	]
};

const RS256_JWK = {
	kty: "RSA",
	n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91pQ",
	e: "AQAB"
};
RS256_JWK.n = replace(RS256_JWK.n, /\+/g, '-');
RS256_JWK.n = replace(RS256_JWK.n, /\//g, '_');

// =============================================================================
// Specifications
// =============================================================================

when("initiating the OIDC login flow", () => {
	let io = create_mock_io();
	io._responses["https://idp.com/.well-known/openid-configuration"] = {
		status: 200,
		body: { 
			issuer: "https://idp.com", 
			authorization_endpoint: "https://idp.com/auth",
			token_endpoint: "https://idp.com/token",
			jwks_uri: "https://idp.com/jwks"
		}
	};

	and("the Identity Provider returns a massive response that exceeds memory limits", () => {
		io._responses["https://idp.com/.well-known/openid-configuration"] = {
			error: "RESPONSE_TOO_LARGE"
		};

		let res = router.handle(io, MOCK_CONFIG, { path: "/" });

		then("it should fail discovery and return a 500 Internal Error", () => {
			assert_eq(res.status, 500);
		});
	});

	and("the Identity Provider is discoverable and healthy", () => {
		io._responses["https://idp.com/.well-known/openid-configuration"] = {
			status: 200,
			body: { 
				issuer: "https://idp.com", 
				authorization_endpoint: "https://idp.com/auth",
				token_endpoint: "https://idp.com/token",
				jwks_uri: "https://idp.com/jwks"
			}
		};

		let res = router.handle(io, MOCK_CONFIG, { path: "/" });

		then("it should return a 302 redirect to the Identity Provider", () => {
			assert_eq(res.status, 302);
			assert(index(res.headers[0], "Location: https://idp.com/auth") == 0);
		});
	});
});

when("processing the OIDC callback", () => {
	
	and("the state and code are valid", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = {
			state: state,
			code_verifier: "verifier123",
			nonce: null,
			issuer_url: "https://idp.com",
			iat: io.time(),
			exp: io.time() + 300
		};
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		io._responses["https://idp.com/.well-known/openid-configuration"] = {
			status: 200,
			body: { 
				issuer: "https://idp.com", 
				authorization_endpoint: "https://idp.com/auth",
				token_endpoint: "https://idp.com/token", 
				jwks_uri: "https://idp.com/jwks" 
			}
		};
		io._responses["https://idp.com/token"] = {
			status: 200,
			body: { access_token: "at", id_token: fixtures.RS256.JWT_TOKEN }
		};
		io._responses["https://idp.com/jwks"] = {
			status: 200,
			body: { keys: [ RS256_JWK ] }
		};
		
		let req = {
			path: "/callback",
			query_string: `code=code123&state=${state}`,
			http_cookie: `luci_sso_state=${state_token}`
		};
		
		// Bypass iss/aud validation by passing nulls, but preserve the mappings!
		let test_config = { ...MOCK_CONFIG, issuer_url: null, client_id: null };
		let res = router.handle(io, test_config, req);

		then("it should redirect to the dashboard", () => {
			assert_eq(res.status, 302);
			assert_eq(res.headers[0], "Location: /cgi-bin/luci/");
		});

		then("it should issue secure LuCI application session cookies", () => {
			assert(index(res.headers[1], "Set-Cookie: sysauth_https=") == 0);
			assert(index(res.headers[2], "Set-Cookie: sysauth=") == 0);
		});

		then("it should clear the temporary handshake state", () => {
			assert(index(res.headers[3], "luci_sso_state=; HttpOnly") >= 0);
		});
	});

	and("the state parameter does not match the signed handshake", () => {
		let io = create_mock_io();
		let handshake = session.create_state(io).data;
		let req = {
			path: "/callback",
			query_string: `code=code123&state=ATTACKER_STATE`,
			http_cookie: `luci_sso_state=${handshake.token}`
		};
		
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should reject the request with a 403 Forbidden", () => {
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