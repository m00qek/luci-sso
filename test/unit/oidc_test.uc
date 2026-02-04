import { test, assert, assert_eq, assert_throws } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

// Mock IO Provider
function create_mock_io() {
	return {
		_files: {},
		_responses: {},
		_posts: [],
		_now: 1516239022 + 10,

		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; },
		http_get: function(url) { 
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return {
				status: res.status,
				body: { read: function() { return raw_body; } }
			};
		},
		http_post: function(url, opts) {
			push(this._posts, { url, opts });
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			return {
				status: res.status,
				body: { read: function() { return raw_body; } }
			};
		}
	};
}

// Fixed RSA JWK matching fixtures.RS256.JWT_PUBKEY
const RS256_JWK = {
	kty: "RSA",
	n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91pQ",
	e: "AQAB"
};
RS256_JWK.n = replace(RS256_JWK.n, /\+/g, '-');
RS256_JWK.n = replace(RS256_JWK.n, /\//g, '_');

// Fixed POLICY JWK matching POLICY.PUBKEY (for expired/mismatch tests)
const POLICY_JWK = {
    kty: "RSA",
    n: "zHsmm0TIiDujMnz6HVQc5B87SGsbKsIQxcCy4XBxNnYka96AjXUC4YzP4rBqefCpgCZIoJN3GSzzrhhd2V_sBgOdcMGY7gWspWt2kTYJ3OqLz9ex2LcQI5ZAf9ggU0BF3DVALIVCl7+Ac52+diC67gMWYMsMZT2iZst9YdGs8NB1GMMzedTQYBUETlF35_wwJSeGRLoWRDa6vnQFe3CxMaXCXXU/6Ceb4ijfuIn3d6l7Y7YsTKJRyFUONazc4ZJRJaXoGekC8qQwyGthAwqzWT8aeB1VysymBC12bTRExlP4mPSsgs60dWgC2g9JXB9IJXTUjtRHMpDbZ5YyDj8oTw",
    e: "AQAB"
};
POLICY_JWK.n = replace(POLICY_JWK.n, /\+/g, '-');
POLICY_JWK.n = replace(POLICY_JWK.n, /\//g, '_');

test('OIDC: Discovery - Schema validation', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let url = issuer + ".well-known/openid-configuration";

	io._responses[url] = { status: 200, body: "<html>Not JSON</html>" };
	assert_eq(oidc.discover(io, issuer).error, "INVALID_JSON", "Should reject non-JSON response");

	io._responses[url] = { status: 200, body: { issuer: issuer } };
	let res = oidc.discover(io, issuer);
	assert_eq(res.error, "MISSING_REQUIRED_FIELD", "Should reject missing endpoints");
});

test('OIDC: Discovery - Cache robustness', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let cache_path = "/tmp/discovery.json";
	
	io._files[cache_path] = "{ invalid json";
	io._responses[issuer + ".well-known/openid-configuration"] = { 
		status: 200, 
		body: { authorization_endpoint: "ok", token_endpoint: "ok", jwks_uri: "ok", issuer: issuer }
	};
	let res = oidc.discover(io, issuer, { cache_path: cache_path });
	assert(res.ok, "Should recover from corrupt cache file");
});

test('OIDC: Token - Successful exchange', () => {
	let io = create_mock_io();
	let discovery = { token_endpoint: "https://idp.com/token" };
	let config = { client_id: "id", client_secret: "secret", redirect_uri: "uri" };
	
	io._responses[discovery.token_endpoint] = {
		status: 200,
		body: { access_token: "at", id_token: "it" }
	};
	
	let res = oidc.exchange_code(io, config, discovery, "code123", "verifier123");
	assert(res.ok, "Code exchange should succeed");
	assert_eq(res.data.access_token, "at", "Should return access token");
});

test('OIDC: ID Token - Valid RS256 signature', () => {
	let io = create_mock_io();
	let tokens = { id_token: fixtures.RS256.JWT_TOKEN };
	let keys = [ RS256_JWK ];
	let res = oidc.verify_id_token(io, tokens, keys, { client_id: null, issuer_url: null }, {});
	assert(res.ok, `Should verify RS256 token, got: ${res.error}`);
	assert_eq(res.data.sub, "1234567890", "Should decode subject correctly");
});

test('OIDC: ID Token - Reject expired token', () => {
	let io = create_mock_io();
	io._now = 2000000000;
	let tokens = { id_token: fixtures.POLICY.JWT_EXPIRED };
	let keys = [ POLICY_JWK ];
	let res = oidc.verify_id_token(io, tokens, keys, { client_id: null, issuer_url: null }, {});
	assert_eq(res.error, "TOKEN_EXPIRED", "Should reject expired tokens");
});

test('OIDC: ID Token - Nonce validation', () => {
	let io = create_mock_io();
	let tokens = { id_token: fixtures.RS256.JWT_TOKEN };
	let keys = [ RS256_JWK ];
	let handshake = { nonce: "mismatch" };
	let res = oidc.verify_id_token(io, tokens, keys, { client_id: null, issuer_url: null }, handshake);
	assert_eq(res.error, "NONCE_MISMATCH", "Should reject if nonce doesn't match handshake");
});

test('OIDC: Flow - Full handshake sequence', () => {
	let io = create_mock_io();
	let discovery = { token_endpoint: "https://idp.com/token" };
	let config = { 
		client_id: null, 
		client_secret: "secret", 
		redirect_uri: "uri",
		issuer_url: null 
	};
	let handshake = { nonce: null };
	let keys = [ RS256_JWK ];

	io._responses[discovery.token_endpoint] = {
		status: 200,
		body: { access_token: "mock_access", id_token: fixtures.RS256.JWT_TOKEN }
	};

	let exchange_res = oidc.exchange_code(io, config, discovery, "code123", "verifier123");
	assert(exchange_res.ok, "Exchange should succeed");

	let verify_res = oidc.verify_id_token(io, exchange_res.data, keys, config, handshake);
	assert(verify_res.ok, "Piping exchange result into verification should work");
	assert_eq(verify_res.data.sub, "1234567890", "Should have correct user data at end of flow");
});

test('OIDC: ID Token - Issuer and Audience mismatch', () => {
	let io = create_mock_io();
	let tokens = { id_token: fixtures.RS256.JWT_TOKEN };
	let keys = [ RS256_JWK ];
	
	let res = oidc.verify_id_token(io, tokens, keys, { issuer_url: "wrong", client_id: null }, {});
	assert_eq(res.error, "ISSUER_MISMATCH", "Should reject wrong issuer");

	res = oidc.verify_id_token(io, tokens, keys, { issuer_url: null, client_id: "wrong" }, {});
	assert_eq(res.error, "AUDIENCE_MISMATCH", "Should reject wrong audience");
});

test('OIDC: ID Token - Malformed structure', () => {
	let io = create_mock_io();
	let res = oidc.verify_id_token(io, { id_token: "not-a-jwt" }, [], {}, {});
	assert_eq(res.error, "INVALID_JWT_HEADER", "Should reject malformed JWT string");
});

test('OIDC: ID Token - JWK conversion failure', () => {
	let io = create_mock_io();
	let token = fixtures.RS256.JWT_TOKEN;
	let keys = [{ kid: "some-kid" }]; 
	let res = oidc.verify_id_token(io, { id_token: token }, keys, {}, {});
	assert_eq(res.error, "MISSING_KTY", "Should fail if JWK is missing required fields");
});