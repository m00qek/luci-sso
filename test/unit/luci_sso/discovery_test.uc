import { describe, it, prop, gen, assert, contains, truthy, falsy, spy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

// discovery.discover / fetch_jwks need the full deps graph (http + fs cache +
// clock + native); with_context builds it from proxies (no stubs). Entry point
// is discovery itself → unit-scoped.
const ISSUER = "https://trusted.idp";

const KEY_RS256 = { kid: 'key-1', kty: 'RSA', alg: 'RS256', use: 'sig' };
const KEY_ES256 = { kid: 'key-2', kty: 'EC',  alg: 'ES256', use: 'sig' };

// ─── find_jwk ────────────────────────────────────────────────────────────────

describe('discovery: find_jwk', () => {
	it('dies with CONTRACT_VIOLATION when keys is not an array', () => {
		assert.throws(() => discovery.find_jwk(null, 'key-1'), /CONTRACT_VIOLATION/);
		assert.throws(() => discovery.find_jwk({},   'key-1'), /CONTRACT_VIOLATION/);
	});

	it('returns NO_KEYS_AVAILABLE when keys is empty and kid is absent', () => {
		assert.match(contains({ ok: false, error: 'NO_KEYS_AVAILABLE' }),
			discovery.find_jwk([], null));
	});

	it('returns the first key when kid is absent and keys is non-empty', () => {
		assert.match(contains({ ok: true, data: KEY_RS256 }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], null));
	});

	it('returns the matching key by kid', () => {
		assert.match(contains({ ok: true, data: KEY_ES256 }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], 'key-2'));
	});

	it('returns KEY_NOT_FOUND when kid does not match any key', () => {
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], 'no-such-key'));
	});

	it('returns KEY_NOT_FOUND when keys is empty and kid is specified', () => {
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			discovery.find_jwk([], 'key-1'));
	});

	// A key in the array is always findable by its own kid.
	prop('find_jwk always finds a key that is present by its kid',
		gen.array(gen.record({ kid: gen.alphanumeric({ min_len: 1, max_len: 10 }) }), { min_len: 1, max_len: 10 }),
		(keys, ctx) => {
			ctx.classify('single key', length(keys) == 1);
			let res = discovery.find_jwk(keys, keys[0].kid);
			assert.match(contains({ ok: true, data: { kid: keys[0].kid } }), res);
		}
	);

	// When no kid is specified, the first element is always returned.
	prop('find_jwk returns the first key when kid is null',
		gen.array(gen.record({ kid: gen.alphanumeric({ min_len: 1, max_len: 10 }) }), { min_len: 1, max_len: 10 }),
		(keys) => {
			assert.match(contains({ ok: true, data: keys[0] }), discovery.find_jwk(keys, null));
		}
	);

	// The complement: a kid absent from the list is never found.
	// '!!!' contains characters gen.alphanumeric() never produces, so it can
	// never collide with any generated kid.
	prop('find_jwk never finds a kid that is absent from the list',
		gen.array(gen.record({ kid: gen.alphanumeric({ min_len: 1, max_len: 10 }) }), { min_len: 0, max_len: 10 }),
		(keys) => {
			assert.match(contains({ ok: false }), discovery.find_jwk(keys, '!!!absent!!!'));
		}
	);
});

// ─── discover — success & caching ──────────────────────────────────────────────

describe('discovery: discover — success & caching', () => {
	it('normalizes the issuer for comparison (trailing slash) (W2)', () => {
		let doc = { ...f.MOCK_DISCOVERY, issuer: ISSUER };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, ISSUER + "/");
			assert.match(truthy(), res.ok, "Should succeed with normalized comparison");
			assert.match(ISSUER, res.data.issuer);
		});
	});

	it('serves a normalized cache hit on a case-different issuer without refetching (W6)', () => {
		let doc = { ...f.MOCK_DISCOVERY, issuer: ISSUER };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			assert.match(truthy(), discovery.discover(deps, ISSUER).ok);
			assert.match(truthy(), discovery.discover(deps, "HTTPS://TRUSTED.IDP").ok, "Should hit cache using normalized comparison (W6)");
			assert.match(1, length(spy(deps.http).calls.get), "Should fetch exactly once");
		});
	});

	it('falls back to a stale cache when the network fails', () => {
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
});

// ─── discover — validation & security ──────────────────────────────────────────

describe('discovery: discover — validation & security', () => {
	// Was the discovery cache written during this run?
	function cache_written(deps) {
		for (let c in (spy(deps.fs).calls.rename || []))
			if (match(c[1], /oidc-discovery-/)) return true;
		return false;
	}

	it('rejects an issuer mismatch and does NOT write the cache (B5)', () => {
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, ISSUER);
			assert.match(falsy(), res.ok, "Should fail on issuer mismatch");
			assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
			assert.match(falsy(), cache_written(deps), "Cache MUST NOT be written when validation fails (B5)");
		});
	});

	it('rejects a doc missing required fields and does NOT write the cache', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: { issuer: ISSUER } } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, ISSUER);
			assert.match(falsy(), res.ok);
			assert.match(falsy(), cache_written(deps), "Cache MUST NOT be written for an incomplete discovery doc");
		});
	});

	it('does not log the raw (malicious) issuer on mismatch (W4)', () => {
		let evil_issuer = "https://evil.com/path?malicious=true";
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: evil_issuer };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let log_entries = [];
			deps.log = (l, m) => push(log_entries, [l, m]);
			discovery.discover(deps, ISSUER);
			let logged = false;
			for (let e in log_entries) {
				logged = true;
				assert.match(-1, index(e[1], evil_issuer), "Raw malicious issuer MUST NOT be logged");
			}
			assert.match(truthy(), logged, "Mismatch error should have been logged");
		});
	});

	it('returns DISCOVERY_NETWORK_ERROR when the cache is missing and the network fails', () => {
		with_context({
			fs:          { data: {} },
			http_client: { behavior: { get: (url, opts) => Result.err("HTTP_REQUEST_FAILED", "DNS_FAILURE") } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, "https://idp.evil.com");
			assert.match(falsy(), res.ok, "Should fail if no cache and no network");
			assert.match("DISCOVERY_NETWORK_ERROR", res.error);
		});
	});

	it('returns an error (does not crash) on an HTTP error response', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { "https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			assert.match(falsy(), discovery.discover(deps, "https://idp.com").ok, "Should return error, not crash");
		});
	});
});

// ─── fetch_jwks ────────────────────────────────────────────────────────────────

describe('discovery: fetch_jwks', () => {
	it('returns an error (does not crash) on an HTTP error response', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { "https://idp.com/jwks": { error: "MOCK_ERROR" } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			assert.match(falsy(), discovery.fetch_jwks(deps, "https://idp.com/jwks").ok, "Should return error, not crash");
		});
	});
});
