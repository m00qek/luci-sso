import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";

// Mock IO Provider for Router Integration
function create_mock_io() {
	return {
		_responses: {},
		_now: 1516239022 + 10,
		_files: { "/etc/luci-sso/secret.key": TEST_SECRET },

		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; },
		http_get: function(url) { 
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		},
		http_post: function(url, opts) {
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return { status: res.status, body: { read: () => raw_body } };
		}
	};
}

const MOCK_CONFIG = {
	issuer_url: "https://idp.com",
	client_id: "client123",
	client_secret: "secret123",
	redirect_uri: "http://router/callback"
};

const RS256_JWK = {
	kty: "RSA",
	n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91pQ",
	e: "AQAB"
};
RS256_JWK.n = replace(RS256_JWK.n, /\+/g, '-');
RS256_JWK.n = replace(RS256_JWK.n, /\//g, '_');

test('Router: Login - Successful redirect initiation', () => {
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

	let req = { path: "/" };
	let res = router.handle(io, MOCK_CONFIG, req);

	assert_eq(res.status, 302, "Should return 302");
	assert(index(res.headers[0], "Location: https://idp.com/auth") == 0, "Should redirect to IdP");
});

test('Router: Callback - Full success flow', () => {
	let io = create_mock_io();
	
	let state = crypto.b64url_encode(crypto.random(16));
	let payload = {
		state: state,
		code_verifier: "verifier123",
		nonce: null,
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
	
	let res = router.handle(io, { ...MOCK_CONFIG, skip_claims: true }, req);

	assert_eq(res.status, 302, "Should redirect on success");
	assert_eq(res.headers[0], "Location: /cgi-bin/luci/", "Should go to LuCI dashboard");
});

test('Router: Callback - Reject CSRF (state mismatch)', () => {
	let io = create_mock_io();
	let handshake = session.create_state(io).data;

	let req = {
		path: "/callback",
		query_string: `code=code123&state=ATTACKER_STATE`,
		http_cookie: `luci_sso_state=${handshake.token}`
	};
	
	let res = router.handle(io, MOCK_CONFIG, req);

	assert_eq(res.status, 403, "Should return 403 Forbidden");
});

test('Router: Global - Handle 404 for unknown paths', () => {

	let io = create_mock_io();

	let res = router.handle(io, MOCK_CONFIG, { path: "/unknown" });

	assert_eq(res.status, 404);

});



test('Router: Logout - Clear session cookie', () => {

	let io = create_mock_io();

	let req = { path: "/logout" };

	let res = router.handle(io, MOCK_CONFIG, req);



	assert_eq(res.status, 302, "Should return 302");

	assert_eq(res.headers[0], "Location: /", "Should redirect to landing page");

	assert(index(res.headers[1], "luci_sso_session=; HttpOnly") >= 0, "Should clear session cookie");

	assert(index(res.headers[1], "Max-Age=0") >= 0, "Should have Max-Age=0");

});
