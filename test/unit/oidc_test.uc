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
		http_get: function(url) { 
			let res = this._responses[url] || { status: 404, body: "" };
			
			// Ensure body is an object with .read() for the library
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			res.body = { read: function() { return raw_body; } };
			
			return res;
		}
	};
}

test('Discovery: Schema validation', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let url = issuer + ".well-known/openid-configuration";

	// 1. Invalid JSON
	io._responses[url] = { status: 200, body: "<html>Not JSON</html>" };
	assert_eq(oidc.discover(io, issuer).error, "INVALID_JSON");

	// 2. Missing required fields
	io._responses[url] = { status: 200, body: { issuer: issuer } };
	let res = oidc.discover(io, issuer);
	assert_eq(res.error, "MISSING_REQUIRED_FIELD");
	assert_eq(res.details, "authorization_endpoint");

	// 3. Wrong types for fields
	io._responses[url] = { status: 200, body: {
		authorization_endpoint: ["should be string"],
		token_endpoint: "valid",
		jwks_uri: "valid"
	}};
	assert_eq(oidc.discover(io, issuer).error, "MISSING_REQUIRED_FIELD");
});

test('Discovery: Cache robustness', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let cache_path = "/tmp/discovery.json";
	
	// 1. Corrupt cache on disk (should ignore and fetch)
	io._files[cache_path] = "{ invalid json";
	let valid_config = { authorization_endpoint: "ok", token_endpoint: "ok", jwks_uri: "ok", issuer: issuer };
	io._responses[issuer + ".well-known/openid-configuration"] = { 
		status: 200, 
		body: valid_config
	};
	let res = oidc.discover(io, issuer, { cache_path: cache_path });
	assert(!res.error, "Should recover from corrupt cache");
	
	// 2. Expired cache
	io._now = 5000;
	io._files[cache_path] = sprintf("%J", { 
		issuer: issuer, 
		authorization_endpoint: "old", 
		token_endpoint: "old",
		jwks_uri: "old",
		cached_at: 1000 // 4000s ago, TTL is 3600
	});
	// Set valid response again for the re-fetch
	io._responses[issuer + ".well-known/openid-configuration"] = { 
		status: 200, 
		body: { authorization_endpoint: "ok", token_endpoint: "ok", jwks_uri: "ok", issuer: issuer }
	};
	res = oidc.discover(io, issuer, { cache_path: cache_path, ttl: 3600 });
	assert(!res.error, "Should not return error on re-fetch");
	assert_eq(res.config.authorization_endpoint, "ok", "Should re-fetch expired cache");
});

test('JWKS: Handle malformed responses', () => {
	let io = create_mock_io();
	let url = "https://idp.com/jwks";

	// 1. Not an array
	io._responses[url] = { status: 200, body: { keys: "not an array" } };
	assert_eq(oidc.fetch_jwks(io, url).error, "INVALID_JWKS_FORMAT");

	// 2. HTTP Error
	io._responses[url] = { status: 403, body: "Forbidden" };
	assert_eq(oidc.fetch_jwks(io, url).error, "JWKS_FETCH_FAILED");
});

test('Auth URL: Edge cases', () => {
	let io = create_mock_io();
	let config = {
		client_id: "client&name=evil",
		redirect_uri: "http://router/cb",
		scope: "openid profile"
	};
	
	// 1. Endpoint with existing query params
	let discovery = { authorization_endpoint: "https://idp.com/auth?tenant=123" };
	let params = { state: "s", nonce: "n", code_challenge: "c" };

	let url = oidc.get_auth_url(io, config, discovery, params);
	assert(index(url, "?tenant=123&") != -1, "Should append with & if ? exists");
	
	// 2. Encoding check
	assert(index(url, "client_id=client&name=evil") != -1);
});

test('Discovery: Trailing slash handling', () => {
	let io = create_mock_io();
	let issuer1 = "https://idp.com";
	let issuer2 = "https://idp.com/";
	let body = { issuer: "https://idp.com/", authorization_endpoint: "a", token_endpoint: "t", jwks_uri: "j" };

	io._responses["https://idp.com/.well-known/openid-configuration"] = { status: 200, body: body };
	io._responses["https://idp.com//.well-known/openid-configuration"] = { status: 200, body: body };

	assert(!oidc.discover(io, issuer1).error);
	assert(!oidc.discover(io, issuer2).error);
});