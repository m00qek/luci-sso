import { describe, it, prop, gen, assert, contains, truthy, falsy, spy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';

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

	it('logs a malicious document issuer only sanitised and capped (W4)', () => {
		// The mismatch line names both issuers so an admin can fix issuer_url.
		// The document's value is IdP-controlled, so it must not be able to
		// forge log lines (no CR/LF or other control bytes) or flood the log.
		let evil_issuer = "https://evil.com/path?malicious=true\r\nluci-sso: forged entry";
		for (let i = 0; i < 300; i++) evil_issuer += "A";
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: evil_issuer };
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let log_entries = [];
			deps.log = (l, m) => push(log_entries, [l, m]);
			discovery.discover(deps, ISSUER);
			assert.match(truthy(), length(log_entries) > 0, "Mismatch error should have been logged");
			for (let e in log_entries) {
				assert.match(-1, index(e[1], evil_issuer), "The raw malicious issuer MUST NOT be logged");
				assert.match(null, match(e[1], /[\r\n]/), "No log line may contain CR or LF");
				assert.match(truthy(), length(e[1]) < 600, "The document issuer must be capped");
			}
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

// ─── discover — schema, cache & hardening ─────────────────────────────────────

describe('discovery: discover — schema, cache & hardening', () => {
	it('successful fetch & schema', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: f.MOCK_DISCOVERY } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer);
			assert.match(truthy(), res.ok);
			assert.match(f.MOCK_DISCOVERY.issuer, res.data.issuer);
		});
	});

	it('handle non-JSON response', () => {
		let issuer = "https://broken.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: "<html>Error</html>" } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer);
			assert.match(falsy(), res.ok);
			assert.match("INVALID_DISCOVERY_DOC", res.error);
		});
	});

	it('reject issuer mismatch', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

		with_context({
			http_client: { data: { [url]: { status: 200, body: evil_doc } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer);
			assert.match(falsy(), res.ok);
			assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);
		});
	});

	it('reject document missing issuer field', () => {
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let bad_doc = { ...f.MOCK_DISCOVERY };
		delete bad_doc.issuer;

		with_context({
			http_client: { data: { [url]: { status: 200, body: bad_doc } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer);
			assert.match(falsy(), res.ok, "Should fail if issuer field is missing");
			assert.match("DISCOVERY_MISSING_ISSUER", res.error);
		});
	});

	it('cache robustness & TTL', () => {
		let issuer = "https://trusted.idp";
		let cache_path = "/var/run/luci-sso/oidc-cache-test.json";
		let url = issuer + "/.well-known/openid-configuration";
		let get_call_count = 0;

		with_context({
			fs: { data: {} },
			http_client: {
				behavior: {
					get: (req_url, opts) => {
						if (req_url == url) {
							get_call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			discovery.discover(deps, issuer, { cache_path, ttl: 100 });

			let before = get_call_count;
			let res = discovery.discover(deps, issuer, { cache_path, ttl: 100 });
			assert.match(truthy(), res.ok, "Should hit cache");
			assert.match(before, get_call_count, "Should not have made a network request");

			before = get_call_count;
			discovery.discover(deps, issuer, { cache_path, ttl: -1 });
			assert.match(before + 1, get_call_count, "Should have attempted network refresh");
		});
	});

	it('immutable cache (no pollution)', () => {
		let issuer = "https://public.idp";
		let url = issuer + "/.well-known/openid-configuration";
		let mock_disc = {
			issuer: issuer,
			authorization_endpoint: issuer + "/auth",
			token_endpoint: issuer + "/token",
			jwks_uri: issuer + "/jwks"
		};

		with_context({
			http_client: { data: { [url]: { status: 200, body: mock_disc } } }
		}, (deps) => {
			let res1 = discovery.discover(deps, issuer);
			assert.match(truthy(), res1.ok);
			res1.data.token_endpoint = "http://EVIL";

			let res2 = discovery.discover(deps, issuer);
			assert.match(issuer + "/token", res2.data.token_endpoint, "Cache must not be polluted");
		});
	});

	it('handle insecure end_session_endpoint', () => {
		let disc = {
			issuer: "https://idp.com",
			authorization_endpoint: "https://idp.com/auth",
			token_endpoint: "https://idp.com/token",
			jwks_uri: "https://idp.com/jwks",
			end_session_endpoint: "http://insecure.com/logout"
		};

		with_context({
			http_client: { data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: disc } } }
		}, (deps) => {
			let res = discovery.discover(deps, "https://idp.com");
			assert.match(truthy(), res.ok);
			assert.match(falsy(), res.data.end_session_endpoint, "Insecure end_session_endpoint MUST be removed");
		});
	});

	it('reject insecure issuer URL', () => {
		with_context({}, (deps) => {
			let res = discovery.discover(deps, "http://insecure.idp");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ISSUER_URL", res.error);
		});
	});

	it('reject insecure internal issuer URL', () => {
		with_context({}, (deps) => {
			let res = discovery.discover(deps, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_FETCH_URL", res.error);
		});
	});

	it('reject discovery document with insecure endpoints', () => {
		let evil_disc = { ...f.MOCK_DISCOVERY, jwks_uri: "http://insecure.idp/jwks" };
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: evil_disc } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ENDPOINT", res.error);
		});
	});

	it('reject massive discovery response (DoS protection)', () => {
		let garbage = "1234567890";
		for (let i = 0; i < 15; i++) garbage += garbage; // 10 * 2^15 = 327,680 chars (~320KB)
		let massive_body = { ...f.MOCK_DISCOVERY, garbage };

		with_context({
			http_client: {
				data: { "https://massive.idp/.well-known/openid-configuration": { status: 200, body: massive_body } }
			}
		}, (deps) => {
			let res = discovery.discover(deps, "https://massive.idp");
			assert.match(falsy(), res.ok, "Should reject massive discovery document");
			assert.match("DISCOVERY_NETWORK_ERROR", res.error, "Should return network error (aborted read)");
		});
	});
});

// ─── fetch_jwks — cache ─────────────────────────────────────────────────────────

describe('discovery: fetch_jwks — cache', () => {
	it('successful fetch, cache & TTL', () => {
		let jwks_uri = "https://trusted.idp/jwks";
		let cache_path = "/var/run/luci-sso/jwks-cache-test.json";
		let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };
		let get_call_count = 0;

		with_context({
			fs: { data: {} },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == jwks_uri) {
							get_call_count++;
							return { ok: true, data: { status: 200, body: sprintf("%J", mock_jwks) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", details: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.fetch_jwks(deps, jwks_uri, { cache_path, ttl: 3600 });
			assert.match(truthy(), res.ok);
			assert.match("k1", res.data[0].kid);

			let before = get_call_count;
			let res2 = discovery.fetch_jwks(deps, jwks_uri, { cache_path, ttl: 3600 });
			assert.match(truthy(), res2.ok, "Should hit cache");
			assert.match(before, get_call_count, "Should not have made a network request");
		});
	});

	it('handle corrupted cache', () => {
		let jwks_uri = "https://trusted.idp/jwks";
		let cache_path = "/var/run/luci-sso/jwks-corrupt.json";
		let mock_jwks = { keys: [ { kid: "k1", kty: "oct", k: "secret" } ] };

		with_context({
			fs: { data: { [cache_path]: "{ invalid json !!! }" } },
			http_client: { data: { [jwks_uri]: { status: 200, body: mock_jwks } } },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.fetch_jwks(deps, jwks_uri, { cache_path });
			assert.match(truthy(), res.ok, "Should fall back to network if cache is corrupted");
			assert.match("k1", res.data[0].kid);
		});
	});
});

// ─── back-channel failure causes reach the log ────────────────────────────────

describe('discovery: HTTP failure causes are logged', () => {
	it('discover logs the transport cause', () => {
		let logs = [];
		with_context({
			http_client: { data: { [ISSUER + "/.well-known/openid-configuration"]: { error: "CERT_UNTRUSTED" } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			assert.match(contains({ ok: false, error: 'DISCOVERY_NETWORK_ERROR' }), discovery.discover(deps, ISSUER));
		});
		assert.match(1, length(filter(logs, (m) => index(m, "Discovery fetch failed") == 0 && index(m, ": HTTP_REQUEST_FAILED (CERT_UNTRUSTED)") > 0)));
	});

	it('fetch_jwks logs the transport cause', () => {
		let logs = [];
		let uri = ISSUER + "/jwks";
		with_context({
			http_client: { data: { [uri]: { error: "TIMED_OUT" } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			assert.match(contains({ ok: false, error: 'JWKS_NETWORK_ERROR' }), discovery.fetch_jwks(deps, uri));
		});
		assert.match(1, length(filter(logs, (m) => index(m, "JWKS fetch failed") == 0 && index(m, ": HTTP_REQUEST_FAILED (TIMED_OUT)") > 0)));
	});
});

// ─── upstream HTTP status: logged, never forwarded ────────────────────────────

describe('discovery: an upstream non-200 is a 502, and its status is logged', () => {
	it('discover returns DISCOVERY_FAILED with 502 for an upstream 404', () => {
		let logs = [];
		let res;
		with_context({
			http_client: { data: { [ISSUER + "/.well-known/openid-configuration"]: { status: 404, body: {} } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			res = discovery.discover(deps, ISSUER);
		});
		assert.match(contains({ ok: false, error: 'DISCOVERY_FAILED' }), res);
		assert.match({ http_status: 502 }, res.details);
		assert.match(1, length(filter(logs, (m) => index(m, "Discovery fetch HTTP 404 from [id: ") == 0)), sprintf("%J", logs));
	});

	it('fetch_jwks returns JWKS_FETCH_FAILED with 502 for an upstream 401', () => {
		let logs = [];
		let uri = ISSUER + "/jwks";
		let res;
		with_context({
			http_client: { data: { [uri]: { status: 401, body: {} } } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			res = discovery.fetch_jwks(deps, uri);
		});
		assert.match(contains({ ok: false, error: 'JWKS_FETCH_FAILED' }), res);
		assert.match({ http_status: 502 }, res.details);
		assert.match(1, length(filter(logs, (m) => index(m, "JWKS fetch HTTP 401 from [id: ") == 0)), sprintf("%J", logs));
	});
});

// ─── split-horizon fetch URL ──────────────────────────────────────────────────

describe('discovery: split-horizon fetch', () => {
	it("fetches from the internal origin with the issuer's path", () => {
		let issuer = "https://kc.example.com/realms/home";
		let doc = { ...f.MOCK_DISCOVERY, issuer: issuer };
		with_context({
			http_client: { data: { "https://10.0.0.5:8443/realms/home/.well-known/openid-configuration": { status: 200, body: doc } } }
		}, (deps) => {
			let res = discovery.discover(deps, issuer, { internal_issuer_url: "https://10.0.0.5:8443" });
			assert.match(contains({ ok: true, data: contains({ issuer: issuer }) }), res);
		});
	});

	it('keeps a trailing slash in the issuer path working (Authentik style)', () => {
		let issuer = "https://auth.example.com/application/o/luci/";
		let doc = { ...f.MOCK_DISCOVERY, issuer: issuer };
		with_context({
			http_client: { data: { "https://10.0.0.6/application/o/luci/.well-known/openid-configuration": { status: 200, body: doc } } }
		}, (deps) => {
			assert.match(contains({ ok: true }), discovery.discover(deps, issuer, { internal_issuer_url: "https://10.0.0.6/" }));
		});
	});

	it('fetches from the issuer itself when there is no internal origin', () => {
		let issuer = "https://kc.example.com/realms/home";
		with_context({
			http_client: { data: { [issuer + "/.well-known/openid-configuration"]: { status: 200, body: { ...f.MOCK_DISCOVERY, issuer } } } }
		}, (deps) => {
			assert.match(contains({ ok: true }), discovery.discover(deps, issuer));
		});
	});
});

// ─── log lines for validation failures ───────────────────────────────────────

describe('discovery: discover — validation failures name themselves in the log', () => {
	function discover_logging(doc) {
		let logs = [];
		let res;
		with_context({
			fs:          { data: {} },
			http_client: { data: { [`${ISSUER}/.well-known/openid-configuration`]: { status: 200, body: doc } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			res = discovery.discover(deps, ISSUER);
		});
		return { res, logs };
	}

	it('logs DISCOVERY_ISSUER_MISMATCH with both issuers, sanitised', () => {
		let r = discover_logging({ ...f.MOCK_DISCOVERY, issuer: "https://evil.idp\r\nforged line" });
		assert.match("DISCOVERY_ISSUER_MISMATCH", r.res.error);
		let line = filter(r.logs, (m) => index(m, "DISCOVERY_ISSUER_MISMATCH: ") == 0);
		assert.match(1, length(line));
		assert.match(truthy(), index(line[0], `issuer_url is "${ISSUER}"`) > 0, line[0]);
		assert.match(truthy(), index(line[0], 'declares "https://evil.idp??forged line"') > 0, line[0]);
		assert.match(null, match(line[0], /[\r\n]/));
	});

	it('logs DISCOVERY_MISSING_ENDPOINT with the missing field and no success line', () => {
		let doc = { ...f.MOCK_DISCOVERY };
		delete doc.token_endpoint;
		let r = discover_logging(doc);
		assert.match("DISCOVERY_MISSING_ENDPOINT", r.res.error);
		assert.match(1, length(filter(r.logs, (m) => index(m, "DISCOVERY_MISSING_ENDPOINT: the discovery document has no token_endpoint") == 0)));
		assert.match(0, length(filter(r.logs, (m) => index(m, "Discovery successful") == 0)));
	});

	it('logs INSECURE_ENDPOINT with the field and a capped, sanitised value', () => {
		let long = "http://insecure.idp/jwks?";
		for (let i = 0; i < 300; i++) long += "a";
		let r = discover_logging({ ...f.MOCK_DISCOVERY, jwks_uri: long + "\nX" });
		assert.match("INSECURE_ENDPOINT", r.res.error);
		let line = filter(r.logs, (m) => index(m, "INSECURE_ENDPOINT: jwks_uri in the discovery document is not HTTPS") == 0);
		assert.match(1, length(line));
		assert.match(truthy(), index(line[0], '"http://insecure.idp/jwks?') > 0);
		assert.match(truthy(), index(line[0], '..."') > 0, 'value must be capped');
		assert.match(null, match(line[0], /[\r\n]/));
	});

	it('logs "Discovery successful" only after the document passed validation', () => {
		let r = discover_logging(f.MOCK_DISCOVERY);
		assert.match(true, r.res.ok);
		assert.match(1, length(filter(r.logs, (m) => index(m, "Discovery successful") == 0)));
	});
});

