import { test, assert, assert_eq } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('discovery: resilience - fallback to stale discovery cache on network failure (W1)', () => {
	let issuer = "https://trusted.idp";
	// We use a fixed hash for the path because we know the safe_id logic
	let cache_path = "/var/run/luci-sso/resilience-test-discovery.json";
	let now = 1516239022;
	
	// Cache is 2 days old (TTL is 1 day)
	let stale_data = { ...f.MOCK_DISCOVERY, cached_at: now - 172800 };

	mock.create()
		.with_files({ [cache_path]: sprintf("%J", stale_data) })
		.with_responses({
			[`${issuer}/.well-known/openid-configuration`]: { error: "CONNECT_FAILED" }
		})
		.spy((io) => {
			// Mock time to 'now'
			io.__state__.now = now;

			let res = discovery.discover(io, issuer, { cache_path: cache_path });
			
			assert(res.ok, "Should succeed using stale cache. Error was: " + (res.error || "none"));
			assert_eq(res.data.issuer, issuer);
			
			// Verify warning was logged
			let found = false;
			for (let e in io.__state__.history) {
				if (e.type == "log" && e.args[0] == "warn" && match(e.args[1], /Using stale discovery cache/)) {
					found = true;
					break;
				}
			}
			assert(found, "Should log warning about stale cache usage");
		});
});

test('discovery: resilience - fallback to stale JWKS cache on network failure', () => {
	let jwks_uri = "https://trusted.idp/jwks";
	let cache_path = "/var/run/luci-sso/resilience-test-jwks.json";
	let now = 1516239022;
	
	let stale_jwks = { keys: [ { kid: "k1" } ], cached_at: now - 172800 };

	mock.create()
		.with_files({ [cache_path]: sprintf("%J", stale_jwks) })
		.with_responses({
			[jwks_uri]: { error: "TIMEOUT" }
		})
		.spy((io) => {
			io.__state__.now = now;
			let res = discovery.fetch_jwks(io, jwks_uri, { cache_path: cache_path });
			
			assert(res.ok, "Should succeed using stale JWKS");
			assert_eq(res.data[0].kid, "k1");
		});
});
