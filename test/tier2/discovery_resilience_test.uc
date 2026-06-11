import { it, assert, truthy, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';

it('discovery: resilience - fallback to stale cache on network failure', () => {
	let issuer = "https://idp.example.com";
	let cache_path = "/var/run/luci-sso/oidc-discovery-stale.json";

	let stale_doc = {
		issuer: issuer,
		authorization_endpoint: "https://idp.example.com/auth",
		token_endpoint: "https://idp.example.com/token",
		jwks_uri: "https://idp.example.com/jwks",
		cached_at: 1000
	};

	with_context({
		fs:          { data: { [cache_path]: sprintf("%J", stale_doc) } },
		http_client: { behavior: { get: (url, opts) => Result.err("HTTP_REQUEST_FAILED", "TIMEOUT") } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer, { cache_path: cache_path });

		assert.match(truthy(), res.ok, "Should fallback to stale cache on network error: " + (res.error || ""));
		assert.match(issuer, res.data.issuer, "Should return cached data");
	});
});

it('discovery: resilience - fail if cache is missing AND network fails', () => {
	let issuer = "https://idp.evil.com";

	with_context({
		fs:          { data: {} },
		http_client: { behavior: { get: (url, opts) => Result.err("HTTP_REQUEST_FAILED", "DNS_FAILURE") } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer);
		assert.match(falsy(), res.ok, "Should fail if no cache and no network");
		assert.match("DISCOVERY_NETWORK_ERROR", res.error);
	});
});
