import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';

// Mock IO Provider
function create_mock_io() {
	return {
		_files: {},
		_responses: {},
		_now: 1000,

		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; },
		urlencode: function(s) { return s; },
		http_get: function(url) { return this._responses[url] || { status: 404, body: "" }; }
	};
}

test('Discovery: Parse valid document and cache it', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let discovery_url = issuer + ".well-known/openid-configuration";
	let mock_config = {
		issuer: issuer,
		authorization_endpoint: "https://mock-idp.com/auth",
		token_endpoint: "https://mock-idp.com/token",
		jwks_uri: "https://mock-idp.com/certs"
	};

	io._responses[discovery_url] = {
		status: 200,
		body: sprintf("%J", mock_config)
	};

	// 1. Initial discovery (should fetch and cache)
	let result = oidc.discover(io, issuer, { cache_path: "/tmp/test-discovery.json" });
	assert(!result.error, `Discovery should succeed, got: ${result.error}`);
	assert_eq(result.config.issuer, issuer);
	
	// Check if it was cached
	assert(io._files["/tmp/test-discovery.json"], "Should have saved to cache");

	// 2. Second discovery (should use cache)
	io._responses[discovery_url] = null; // Clear network
	let result2 = oidc.discover(io, issuer, { cache_path: "/tmp/test-discovery.json" });
	assert(!result2.error, "Discovery from cache should succeed");
	assert_eq(result2.config.issuer, issuer);
});

test('Discovery: Handle network failure', () => {
	let io = create_mock_io();
	let issuer = "https://broken-idp.com/";
	io._responses[issuer + ".well-known/openid-configuration"] = { status: 500, body: "" };

	let result = oidc.discover(io, issuer, { cache_path: "/tmp/broken.json" });
	assert(result.error, "Should return error on network failure");
});

test('JWKS: Find key by kid', () => {
	let keys = [
		{ kid: "key1", kty: "RSA", n: "...", e: "AQAB" },
		{ kid: "key2", kty: "RSA", n: "...", e: "AQAB" }
	];
	
	let result = oidc.find_jwk(keys, "key2");
	assert(!result.error, "Should find key");
	assert_eq(result.jwk.kid, "key2", "Should return correct key");
});

test('JWKS: Handle missing kid', () => {
	let keys = [
		{ kid: "key1", kty: "RSA", n: "...", e: "AQAB" }
	];
	
	let result = oidc.find_jwk(keys, null);
	assert(!result.error, "Should return first key if no kid specified");
	assert_eq(result.jwk.kid, "key1");
});

test('JWKS: Handle key not found', () => {
	let keys = [
		{ kid: "key1", kty: "RSA", n: "...", e: "AQAB" }
	];
	
	let result = oidc.find_jwk(keys, "nonexistent");
	assert_eq(result.error, "KEY_NOT_FOUND", "Should return error");
});

test('Auth URL: Correct parameters', () => {
	let io = create_mock_io();
	let config = {
		client_id: "my-client",
		redirect_uri: "http://router/cb",
		scope: "openid profile"
	};
	let discovery = {
		authorization_endpoint: "https://idp.com/authorize"
	};

	let auth = oidc.get_auth_url(io, config, discovery);
	assert(!auth.error);
	assert(index(auth.url, "client_id=my-client") != -1, "URL should contain client_id");
	assert(index(auth.url, "response_type=code") != -1, "URL should contain response_type");
	assert(index(auth.url, "nonce=" + auth.nonce) != -1, "URL should contain nonce");
	assert(auth.state, "Should generate a state");
	assert(auth.nonce, "Should generate a nonce");
	assert(auth.code_verifier, "Should generate a PKCE verifier");
});
