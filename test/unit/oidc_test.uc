import { test, assert, assert_eq, assert_throws } from 'testing';
import * as oidc from 'luci_sso.oidc';

// Mock IO Provider
function create_mock_io() {
	return {
		_files: {},
		_responses: {},
		_posts: [],
		_now: 1000,

		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; },
		http_get: function(url) { 
			let res = this._responses[url] || { status: 404, body: "" };
			
			// Ensure body is an object with .read() for the library
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			let response = {
				status: res.status,
				body: { read: function() { return raw_body; } }
			};
			
			return response;
		},
		http_post: function(url, opts) {
			push(this._posts, { url, opts });
			let res = this._responses[url] || { status: 404, body: "" };
			let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
			let response = {
				status: res.status,
				body: { read: function() { return raw_body; } }
			};
			return response;
		}
	};
}

test('Discovery: Schema validation', () => {
	let io = create_mock_io();
	let issuer = "https://mock-idp.com/";
	let url = issuer + ".well-known/openid-configuration";

	// 1. Invalid JSON
	io._responses[url] = { status: 200, body: "<html>Not JSON</html>" };
	let res_json = oidc.discover(io, issuer);
	assert(!res_json.ok);
	assert_eq(res_json.error, "INVALID_JSON");

	// 2. Missing required fields
	io._responses[url] = { status: 200, body: { issuer: issuer } };
	let res = oidc.discover(io, issuer);
	assert(!res.ok);
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
	assert(res.ok, "Should recover from corrupt cache");
	
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
	assert(res.ok, "Should not return error on re-fetch");
	assert_eq(res.data.authorization_endpoint, "ok", "Should re-fetch expired cache");
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

test('Token Exchange: Success', () => {
	let io = create_mock_io();
	let discovery = { token_endpoint: "https://idp.com/token" };
	let config = { client_id: "id", client_secret: "secret", redirect_uri: "uri" };
	
	io._responses[discovery.token_endpoint] = {
		status: 200,
		body: { access_token: "at", id_token: "it" }
	};
	
	let res = oidc.exchange_code(io, config, discovery, "code123", "verifier123");
	assert(res.ok, `Exchange failed: ${res.error}`);
	assert_eq(res.data.access_token, "at");
	
	assert_eq(io._posts[0].url, discovery.token_endpoint);
	assert(index(io._posts[0].opts.body, "code=code123") >= 0);
	assert(index(io._posts[0].opts.body, "code_verifier=verifier123") >= 0);
});