import { test, assert, assert_eq } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Discovery Resilience (Stale Cache Fallback)
// =============================================================================

test('discovery: resilience - fallback to stale cache on network failure', () => {
	let factory = mock.create();
	let issuer = "https://idp.example.com";
	let cache_path = "/var/run/luci-sso/oidc-discovery-stale.json";
	
	let stale_doc = {
		issuer: issuer,
		authorization_endpoint: "https://idp.example.com/auth",
		token_endpoint: "https://idp.example.com/token",
		jwks_uri: "https://idp.example.com/jwks",
		cached_at: 1000 // Very old
	};

	factory.with_files({
		[cache_path]: sprintf("%J", stale_doc)
	}, (io) => {
		// Mock current time way past TTL (e.g. 1 week later)
		io.time = () => 1000000;

		// Mock network failure (timeout)
		io.http_get = (url) => Result.err("TIMEOUT");

		let res = discovery.discover(io, issuer, { cache_path: cache_path });
		
		assert(res.ok, "Should fallback to stale cache on network error: " + (res.error || ""));
		assert_eq(res.data.issuer, issuer, "Should return cached data");
	});
});

test('discovery: resilience - fail if cache is missing AND network fails', () => {
	let factory = mock.create();
	let issuer = "https://idp.evil.com";

	factory.with_env({}, (io) => {
		io.http_get = (url) => Result.err("DNS_FAILURE");

		let res = discovery.discover(io, issuer);
		assert(!res.ok, "Should fail if no cache and no network");
		assert_eq(res.error, "NETWORK_ERROR");
	});
});
