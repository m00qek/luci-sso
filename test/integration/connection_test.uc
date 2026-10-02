import { describe, it, assert, contains, spy, regex } from 'utest';
import * as connection from 'luci_sso.connection';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as native from 'luci_sso.native';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Integration bucket — enter at connection.check, the settings page's
// connection test. It runs the login's real discovery, JWK Set and token
// request code (discovery + oidc + crypto, REAL native) against a faked HTTP
// boundary, and asserts each check's pass and fail, and that it touches no
// cache and never echoes or logs the client secret.

const ISSUER = f.MOCK_CONFIG.issuer_url;
const DISC = ISSUER + "/.well-known/openid-configuration";
const SECRET = "s3cr3t-Value-!";
const REDIRECT = "https://router.example.com/cgi-bin/luci-sso/callback";

// Keys the native backends refuse for an ID token, made for these tests.
// A 1024-bit RSA key, exponent 65537, with its private key to sign with.
const WEAK_1024_JWK = {
	kty: "RSA", kid: "weak-1024", e: "AQAB",
	n: "sDEddzQN7sIus8ghCGwJpYOEkBtHbohg0A3uXavdjuOpcTE2IIgpg42PDtxiaNxdHjt_sbh3jl-hZhs1uhq-y37rldPOumsyyg2hZJu1j5I1-iJJlyaCIjeDGhc5QyoJ1Sl8iZfKNRgOYBPiqHyto7YwdAkPzufh1o_JmranYQ0"
};
const WEAK_1024_PRIVKEY = "-----BEGIN PRIVATE KEY-----\n" +
	"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALAxHXc0De7CLrPI\n" +
	"IQhsCaWDhJAbR26IYNAN7l2r3Y7jqXExNiCIKYONjw7cYmjcXR47f7G4d45foWYb\n" +
	"Nboavst+65XTzrprMsoNoWSbtY+SNfoiSZcmgiI3gxoXOUMqCdUpfImXyjUYDmAT\n" +
	"4qh8raO2MHQJD87n4daPyZq2p2ENAgMBAAECgYBSX6QXBw88gSy0gOxws5IO/94K\n" +
	"Qbazxq78lobK5H9BPs8JTKixrPc7ugMYP5EC1YPzjn206Tl8JtmekzobOEXat1Zv\n" +
	"FO9RgbyPgCTlfFchTYENhgQWKlycDPoZrSiZ8IFfX3Vz96xIgVAMxvxVyoGG+yte\n" +
	"NEJzCj9rnY0k6uuUAQJBANv05j5KTEurRZQyyCFYRi1u6fqSNiBLqpjh43IVDdlw\n" +
	"KFYcUI3LH3vIem3UAls3cZ5FFynBvpZlcmgboEc+SxECQQDNEEyQlZ8KsPLKAViw\n" +
	"70la3ZAptUWh7bDjjtfwHiIfT53YrsyDgsJY03tQKFe8eJbqtyYQ5TJNDcmk/+eE\n" +
	"y549AkEAqZwnD1Frk832UVj3Sf8v3kjw0+97HVw7qLhHEul5THpYIE6lLzG6jVEC\n" +
	"Vz5ssroGOu07908XEBIaLn1fEpDOgQJAAgsQiDxFamja8nJS/OhVdcdRYWkB+ZwR\n" +
	"sCLDOgxC0McNTpRnS0QpRZNN3j2YqjMVZd9PTMnL14K0qKU4HFWfDQJBALAwUdWr\n" +
	"X669yeaN1XNa0uZMC/+Mym+jIPk0nUeKJdGtgUFsUDokPcYCU2UlqUU2aZ/BT9i1\n" +
	"RI5W6F9nva1bcUY=\n" +
	"-----END PRIVATE KEY-----";
// A 2047-bit modulus: 256 bytes, the top bit clear.
const N_2047 = "SzH5mg-p0YHIxFKIe2giwiGJY2iaHLwG680IlcfTFrl14LJ7FyY_fqf3ktGsVzJM3UxQV5vjm1pJoa_1jWH4WA1cRwbyk9Pl_H1MoOmtDWgxDxh6UQHMmv06LaQnUvDwrVDB3569gZPCx8MCNG92v-CgQrjCL0CDPz8YCSOVveoHdL1zWgdeArpTLMGXMq1oB8fXhuRC7ceHJKyRBUjfHmoqMqmohcTRw6ofd0MGBrigNwQo_4i3-1PHH8dQDLbVBPjESOKRc9mdAeqV9izoj2PyXEqrnSs0lD8W631gmj5aMkYtS8gLRQFIVpVDYUWNC4HmJcC3mkai0vs75OI8lw";
// A 2048-bit RSA key with the public exponent 3.
const E3_JWK = {
	kty: "RSA", kid: "e3", e: "Aw",
	n: "2A_DHi6B9nN91XxHC1amrfUX93N7-hzn4gUr-4BFZ4lwu93n1gxMK83WvH7ZNN7_K67WWF3GYQuBRYwrVC1F_aVEKwYI6mjy-ktrgZQ_HNiwH_VRXGuU8uohN70D9mwWQb6S2Xjhywuo3sjiYg2DXNQKJG66zE2bSNvntJrOW1kfDBRi8OyLIc8WwTJpKZpEq_YoTn7gHxu0jG76gnS-aJC47k_fo2PPukiYQH83DHodV8UBryDklI5UmRuFdblJTEY415Xty9rDBDjDbGFsHv4ufOo83lAXWEJlAn_YFWZD8jmHYfjS8BTrpdO0FEJ1_gj_VmqLUEpiGx4bNAUQeQ"
};
// An EC key on P-384.
const P384_JWK = {
	kty: "EC", kid: "p384", crv: "P-384",
	x: "bOMXaPjvCM3S-gUO8Lxc7K9jA_t6EvSLEm89oS_PmSV6ULVEKsC7vn_98-8EvbQf",
	y: "jBXp0wabqeIA49QuRaTY-l0sNoV2Hzm-QSIYOgxNyQlsFC_lDDz2drgK1y30L3ir"
};

const PARAMS = {
	issuer_url: ISSUER,
	internal_issuer_url: "",
	client_id: f.MOCK_CONFIG.client_id,
	client_secret: SECRET,
	redirect_uri: REDIRECT,
};

// The IdP as the mock serves it: every check passes.
function idp(over) {
	return {
		[DISC]: { status: 200, body: f.MOCK_DISCOVERY },
		[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
		[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } },
		...(over || {})
	};
}

// Runs the test; returns { checks: { id: {status, message} }, order, logs, posts, fs_calls, gets }.
function run(params, http) {
	let out = { checks: {}, order: [], logs: [], posts: [], gets: [], fs_calls: {} };
	with_context({
		fs:          { data: {} },
		http_client: { data: http || idp() },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		deps.log = (l, m) => push(out.logs, [ l, m ]);
		let res = connection.check(deps, { ...PARAMS, ...(params || {}) });
		assert.match(true, res.ok);
		for (let c in res.data.checks) {
			out.checks[c.id] = { status: c.status, message: c.message };
			push(out.order, c.id);
		}
		out.raw = res.data;
		out.posts = spy(deps.http).calls.post || [];
		out.gets = map(spy(deps.http).calls.get || [], (c) => c[0]);
		out.fs_calls = spy(deps.fs).calls;
	});
	return out;
}

function status_of(r) {
	let out = {};
	for (let id, c in r.checks) out[id] = c.status;
	return out;
}

const ALL_PASS = {
	issuer_https: "pass", discovery: "pass", issuer_match: "pass", endpoints: "pass",
	jwks: "pass", redirect_uri: "pass", client_credentials: "pass"
};

describe('connection: check — a working provider', () => {
	it('passes every check, in order', () => {
		let r = run();
		assert.match([ "issuer_https", "discovery", "issuer_match", "endpoints", "jwks", "redirect_uri", "client_credentials" ], r.order);
		assert.match(ALL_PASS, status_of(r));
		assert.match(contains({ message: `Fetched the discovery document from ${DISC}.` }), r.checks.discovery);
		assert.match(contains({ message: "The JWK Set has 1 key(s); every key a login would pick can verify ID tokens (RS256, or ES256 on P-256). Keys: 'test-key-1': can verify ID tokens." }), r.checks.jwks);
	});

	it('probes the token endpoint as a login does: client_secret_post, a made-up code and a fresh PKCE verifier', () => {
		let r = run();
		assert.match(1, length(r.posts));
		assert.match(f.MOCK_DISCOVERY.token_endpoint, r.posts[0][0]);
		let body = {};
		for (let kv in split(r.posts[0][1].body, "&")) {
			let p = split(kv, "=", 2);
			body[p[0]] = p[1];
		}
		assert.match([ "grant_type", "client_id", "client_secret", "redirect_uri", "code", "code_verifier" ], keys(body));
		assert.match("authorization_code", body.grant_type);
		assert.match(f.MOCK_CONFIG.client_id, body.client_id);
		assert.match(SECRET, body.client_secret);
		assert.match(true, index(body.code, "luci-sso-connection-test-") == 0, body.code);
		assert.match(true, length(body.code_verifier) >= 43, body.code_verifier);

		let again = run();
		let code2 = match(again.posts[0][1].body, /code=([^&]+)/)[1];
		assert.match(true, code2 != body.code, "each test makes up a new code");
	});

	it('neither reads nor writes the discovery or JWK Set cache', () => {
		let r = run();
		for (let fn, calls in r.fs_calls)
			for (let c in calls)
				assert.match(null, match(`${c[0]} ${c[1]}`, /oidc-(discovery|jwks)-/), `${fn} ${c[0]}`);
	});

	it('never puts the client secret in a message or a log line', () => {
		for (let token in [ { status: 400, body: { error: "invalid_grant" } }, { status: 401, body: { error: "invalid_client" } },
		                    { status: 500, body: "" }, { error: "TIMED_OUT" } ]) {
			let r = run(null, idp({ [f.MOCK_DISCOVERY.token_endpoint]: token }));
			assert.match(-1, index(sprintf("%J", r.raw), "s3cr3t"), sprintf("%J", token));
			for (let l in r.logs) assert.match(-1, index(l[1], "s3cr3t"), l[1]);
		}
	});

	it('logs its lines with a "Connection test:" prefix, and a summary', () => {
		let r = run();
		assert.match(0, length(filter(r.logs, (l) => index(l[1], "Connection test: ") != 0)), sprintf("%J", r.logs));
		assert.match(1, length(filter(r.logs, (l) => l[1] == "Connection test: finished: 7 passed, 0 failed, 0 undetermined, 0 skipped")));
	});

	it('logs the credential probe\'s expected refusal at info, not as an error', () => {
		let r = run();
		let refusal = filter(r.logs, (l) => index(l[1], "invalid_grant") >= 0);
		assert.match(1, length(refusal), sprintf("%J", r.logs));
		assert.match("info", refusal[0][0]);
	});
});

describe('connection: check — issuer URL', () => {
	it('fails an empty issuer URL, and skips the checks that need it', () => {
		let r = run({ issuer_url: "" });
		assert.match(contains({ status: "fail" }), r.checks.issuer_https);
		for (let id in [ "discovery", "issuer_match", "endpoints", "jwks", "client_credentials" ])
			assert.match("skip", r.checks[id].status, id);
		assert.match("pass", r.checks.redirect_uri.status, "the redirect URI is still checked");
		assert.match([], r.gets, "nothing is fetched");
	});

	it('fails a plain-HTTP issuer URL', () => {
		let r = run({ issuer_url: "http://trusted.idp" });
		assert.match({ status: "fail", message: "Issuer URL must start with https://." }, r.checks.issuer_https);
		assert.match([], r.gets);
	});

	it('reports an issuer that differs only in a trailing slash with the same hint as the log', () => {
		let r = run({ issuer_url: ISSUER + "/" }, idp({ [ISSUER + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY } }));
		assert.match("pass", r.checks.discovery.status);
		assert.match({ status: "fail", message: `The provider declares "${ISSUER}", but Issuer URL is "${ISSUER}/". They differ only in a trailing slash, letter case or default port: set Issuer URL to exactly the declared value.` },
			r.checks.issuer_match);
		for (let id in [ "endpoints", "jwks", "client_credentials" ])
			assert.match("skip", r.checks[id].status, id);
	});

	it('quotes the provider\'s values with "<" and ">" as "?", so no message carries markup', () => {
		let hostile = 'https://x/<img src=x onerror="window.__xss=1">';
		let r = run(null, idp({ [DISC]: { status: 200, body: { ...f.MOCK_DISCOVERY, issuer: hostile } } }));
		assert.match(true, index(r.checks.issuer_match.message, 'The provider declares "https://x/?img src=x onerror="window.__xss=1"?"') == 0,
			r.checks.issuer_match.message);

		let bad_jwks = f.MOCK_DISCOVERY.jwks_uri + "?<b>";
		let j = run(null, idp({ [DISC]: { status: 200, body: { ...f.MOCK_DISCOVERY, jwks_uri: bad_jwks } }, [bad_jwks]: { status: 500, body: "" } }));
		assert.match({ status: "fail", message: `${f.MOCK_DISCOVERY.jwks_uri}??b? answered HTTP 500.` }, j.checks.jwks);

		// oidc.exchange_code keeps only an error code made of [A-Za-z0-9_.:-].
		let t = run(null, idp({ [f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "<script>x</script>" } } }));
		assert.match({ status: "warn", message: "Couldn't determine whether the Client ID and Client Secret are right: the provider answered HTTP 400." }, t.checks.client_credentials);
	});

	it('reports a different issuer without the near-miss hint', () => {
		let r = run(null, idp({ [DISC]: { status: 200, body: { ...f.MOCK_DISCOVERY, issuer: "https://other.idp" } } }));
		assert.match(contains({ status: "fail" }), r.checks.issuer_match);
		assert.match(true, index(r.checks.issuer_match.message, 'The provider declares "https://other.idp"') == 0);
		assert.match(-1, index(r.checks.issuer_match.message, "trailing slash"));
	});

	it('fails a discovery document without an issuer', () => {
		let doc = { ...f.MOCK_DISCOVERY };
		delete doc.issuer;
		let r = run(null, idp({ [DISC]: { status: 200, body: doc } }));
		assert.match("pass", r.checks.discovery.status);
		assert.match({ status: "fail", message: "The discovery document declares no issuer." }, r.checks.issuer_match);
	});
});

describe('connection: check — discovery', () => {
	it('reports a timeout in plain words', () => {
		let r = run(null, idp({ [DISC]: { error: "TIMED_OUT" } }));
		assert.match({ status: "fail", message: `No answer from ${DISC} within 5 seconds.` }, r.checks.discovery);
		for (let id in [ "issuer_match", "endpoints", "jwks", "client_credentials" ])
			assert.match("skip", r.checks[id].status, id);
	});

	it('reports an untrusted certificate, a refused connection and any other cause', () => {
		assert.match(true, index(run(null, idp({ [DISC]: { error: "CERT_UNTRUSTED" } })).checks.discovery.message, "does not trust the certificate") > 0);
		assert.match(true, index(run(null, idp({ [DISC]: { error: "CONNECTION_FAILED" } })).checks.discovery.message, "Could not connect to") == 0);
		assert.match(`Could not fetch ${DISC} (HTTP_REQUEST_FAILED (UCLIENT_ERROR_5)).`, run(null, idp({ [DISC]: { error: "UCLIENT_ERROR_5" } })).checks.discovery.message);
	});

	it('reports the HTTP status of a failed fetch', () => {
		let r = run(null, idp({ [DISC]: { status: 404, body: "" } }));
		assert.match(contains({ status: "fail" }), r.checks.discovery);
		assert.match(true, index(r.checks.discovery.message, `${DISC} answered HTTP 404.`) == 0);
	});

	it('fails a body that is not a JSON discovery document', () => {
		let r = run(null, idp({ [DISC]: { status: 200, body: "<html>" } }));
		assert.match({ status: "fail", message: `${DISC} did not return a JSON discovery document.` }, r.checks.discovery);
	});

	it('fetches from the internal issuer URL, and sends the back channel there too, as at login', () => {
		let internal = "https://10.0.0.5:8443";
		let r = run({ internal_issuer_url: internal }, {
			[internal + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
			[internal + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
			[internal + "/token"]: { status: 400, body: { error: "invalid_grant" } },
		});
		assert.match(ALL_PASS, status_of(r));
		assert.match([ internal + "/.well-known/openid-configuration", internal + "/jwks" ], r.gets);
		assert.match(internal + "/token", r.posts[0][0]);
	});

	it('fails an internal issuer URL that is not an HTTPS origin, without fetching', () => {
		for (let bad in [ "http://10.0.0.5", "https://10.0.0.5/realms/home" ]) {
			let r = run({ internal_issuer_url: bad });
			assert.match(contains({ status: "fail" }), r.checks.discovery, bad);
			assert.match(true, index(r.checks.discovery.message, "Internal Issuer URL must be an HTTPS origin") == 0, bad);
			assert.match([], r.gets, bad);
		}
	});
});

describe('connection: check — endpoints', () => {
	it('fails a document without a required endpoint', () => {
		for (let field in [ "authorization_endpoint", "token_endpoint", "jwks_uri" ]) {
			let doc = { ...f.MOCK_DISCOVERY };
			delete doc[field];
			let r = run(null, idp({ [DISC]: { status: 200, body: doc } }));
			assert.match("pass", r.checks.issuer_match.status, field);
			assert.match({ status: "fail", message: `The discovery document has no ${field}.` }, r.checks.endpoints, field);
			assert.match("skip", r.checks.jwks.status);
			assert.match("skip", r.checks.client_credentials.status);
		}
	});

	it('fails an endpoint that is not HTTPS', () => {
		let r = run(null, idp({ [DISC]: { status: 200, body: { ...f.MOCK_DISCOVERY, token_endpoint: "http://trusted.idp/token" } } }));
		assert.match({ status: "fail", message: "The token_endpoint in the discovery document does not use HTTPS." }, r.checks.endpoints);
	});
});

describe('connection: check — signing keys', () => {
	const JWKS = f.MOCK_DISCOVERY.jwks_uri;

	it('fails when the JWK Set cannot be fetched, or is not a JWK Set', () => {
		assert.match({ status: "fail", message: `No answer from ${JWKS} within 5 seconds.` }, run(null, idp({ [JWKS]: { error: "TIMED_OUT" } })).checks.jwks);
		assert.match({ status: "fail", message: `${JWKS} answered HTTP 500.` }, run(null, idp({ [JWKS]: { status: 500, body: "" } })).checks.jwks);
		assert.match(contains({ status: "fail" }), run(null, idp({ [JWKS]: { status: 200, body: { nokeys: true } } })).checks.jwks);
	});

	const GENERAL = "No key a login would pick can verify ID tokens: luci-sso needs an RSA key of at least 2048 bits with the exponent 65537, or an EC key on P-256.";
	const jwks = (keys) => run(null, idp({ [JWKS]: { status: 200, body: { keys } } })).checks.jwks;

	it('fails a JWK Set with no key a login would pick that can verify ID tokens, and describes each key', () => {
		let r = jwks([
			{ kty: "oct", k: "c2VjcmV0" },
			{ ...f.MOCK_JWK, alg: "RS512" },
			{ ...f.MOCK_JWK, kid: "k3", alg: "ES256" },
			P384_JWK,
			{ kty: "RSA", n: "!!", e: "AQAB" },
			"not a key",
		]);
		assert.match({ status: "fail", message: GENERAL + " Keys: " +
			"#1: neither an RSA key nor an EC key on P-256; " +
			"'test-key-1': a key for \"RS512\", an algorithm luci-sso does not accept for it; " +
			"'k3': a key for \"ES256\", an algorithm luci-sso does not accept for it; " +
			"'p384': neither an RSA key nor an EC key on P-256; " +
			"#5: malformed: it cannot be read as an RSA or EC public key; a login never picks it; " +
			"#6: not a JSON object; a login never picks it." }, r);
	});

	it('fails an empty JWK Set', () => {
		assert.match({ status: "fail", message: "The JWK Set has no keys." }, jwks([]));
	});

	it('passes when every key a login would pick can verify ID tokens', () => {
		assert.match({ status: "pass", message: "The JWK Set has 1 key(s); every key a login would pick can verify ID tokens (RS256, or ES256 on P-256). Keys: 'test-key-1': can verify ID tokens." },
			jwks([ f.MOCK_JWK ]));
		assert.match({ status: "pass", message: "The JWK Set has 2 key(s); every key a login would pick can verify ID tokens (RS256, or ES256 on P-256). Keys: 'test-key-1': can verify ID tokens; 'rot': can verify ID tokens." },
			jwks([ { ...f.MOCK_JWK, alg: "RS256", use: "sig" }, { ...f.MOCK_JWK, kid: "rot" } ]));
	});

	it('warns when the first key cannot verify: an ID token without a kid would fail', () => {
		assert.match({ status: "warn", message: "An ID token without a kid would fail: a login checks it with the first key, 'weak-1024', which is an RSA key of 1024 bits, under 2048. " +
			"Tokens a login checks with 'test-key-1' verify. Keys: 'weak-1024': an RSA key of 1024 bits, under 2048; 'test-key-1': can verify ID tokens." },
			jwks([ WEAK_1024_JWK, f.MOCK_JWK ]));
		assert.match(contains({ status: "warn" }), jwks([ { kty: "oct", k: "c2VjcmV0" }, f.MOCK_JWK ]), "a symmetric key first");
		assert.match(contains({ status: "warn" }), jwks([ "not a key", f.MOCK_JWK ]), "an entry that is not a key first");
	});

	it('warns when a signing key a login picks by its kid cannot verify', () => {
		assert.match({ status: "warn", message: "An ID token naming 'e3' would fail. Tokens a login checks with 'test-key-1' verify. " +
			"Keys: 'test-key-1': can verify ID tokens; 'e3': an RSA key whose public exponent is not 65537 (AQAB)." },
			jwks([ f.MOCK_JWK, E3_JWK ]));
	});

	it('judges a key whatever its use, as a login does: a single encryption-marked key a login verifies with passes', () => {
		assert.match(contains({ status: "pass", message: regex(/'test-key-1': can verify ID tokens; not for signing \(use "enc"\)\.$/) }),
			jwks([ { ...f.MOCK_JWK, use: "enc" } ]));
	});

	it('never fails or warns over an encryption key a login picks only by its kid', () => {
		let r = jwks([ f.MOCK_JWK, { ...P384_JWK, use: "enc" } ]);
		assert.match(contains({ status: "pass", message: regex(/'p384': neither an RSA key nor an EC key on P-256; not for signing \(use "enc"\)\.$/) }), r);
	});

	it('warns when the first key is an encryption key it cannot verify with: a token without a kid is checked with it', () => {
		assert.match(contains({ status: "warn", message: regex(/^An ID token without a kid would fail: a login checks it with the first key, 'p384'/) }),
			jwks([ { ...P384_JWK, use: "enc" }, f.MOCK_JWK ]));
	});

	it('says which keys a login never picks, and does not judge the set by them', () => {
		assert.match(contains({ status: "pass", message: regex(/#2: an RSA key of 1024 bits, under 2048; a login never picks it\.$/) }),
			jwks([ f.MOCK_JWK, { kty: "RSA", n: WEAK_1024_JWK.n, e: "AQAB" } ]), "no kid, and not the first");
		assert.match(contains({ status: "pass", message: regex(/'test-key-1': an RSA key of 1024 bits, under 2048; a login never picks it\.$/) }),
			jwks([ f.MOCK_JWK, { ...WEAK_1024_JWK, kid: f.MOCK_JWK.kid } ]), "the same kid as an earlier key");
	});

	it('describes a malformed key, without a crash: n, e, x or y that is not a string', () => {
		for (let bad in [ { kty: "RSA", kid: "odd", n: 12345, e: "AQAB" }, { kty: "RSA", kid: "odd", n: f.MOCK_JWK.n, e: 65537 },
		                  { kty: "EC", crv: "P-256", kid: "odd", x: 5, y: "AA" }, { kty: "EC", crv: "P-256", kid: "odd", x: "AA", y: [ 1 ] } ]) {
			assert.match({ status: "warn", message: "An ID token naming 'odd' would fail. Tokens a login checks with 'test-key-1' verify. " +
				"Keys: 'test-key-1': can verify ID tokens; 'odd': malformed: it cannot be read as an RSA or EC public key." }, jwks([ f.MOCK_JWK, bad ]), sprintf("%J", bad));
			assert.match(contains({ status: "fail", message: regex(/^No key a login would pick/) }), jwks([ bad ]), sprintf("%J", bad));
		}
	});

	it('describes at most ten keys one by one', () => {
		let keys = [ f.MOCK_JWK ];
		for (let i = 0; i < 14; i++) push(keys, { ...f.MOCK_JWK, kid: `k${i}` });
		let m = jwks(keys).message;
		assert.match(true, index(m, "'k8': can verify ID tokens; and 5 more.") > 0, m);
		assert.match(-1, index(m, "'k9'"));
	});

	it('shows a kid made safe for the page and the log', () => {
		let m = jwks([ { ...f.MOCK_JWK, kid: "<img src=x>\n" } ]).message;
		assert.match(true, index(m, "'?img src=x??': can verify ID tokens") > 0, m);
	});
});

// The keys a login can verify with are the ones the native backends accept:
// an RSA modulus of at least 2048 bits, the exponent 65537 only, and EC on
// P-256. The connection test must judge them the same way, or it passes a
// provider whose every login then fails with INVALID_SIGNATURE.
describe('connection: check — signing keys, judged as a login judges them', () => {
	const JWKS = f.MOCK_DISCOVERY.jwks_uri;
	const jwks = (keys) => run(null, idp({ [JWKS]: { status: 200, body: { keys } } })).checks.jwks;

	it('fails an RSA key under 2048 bits, and says how long it is', () => {
		assert.match({ status: "fail", message: "The provider's RSA key is 1024 bits; luci-sso requires at least 2048. Keys: 'weak-1024': an RSA key of 1024 bits, under 2048." }, jwks([ WEAK_1024_JWK ]));
		assert.match({ status: "fail", message: "The provider's RSA key is 2047 bits; luci-sso requires at least 2048. Keys: #1: an RSA key of 2047 bits, under 2048." }, jwks([ { kty: "RSA", n: N_2047, e: "AQAB" } ]));
		assert.match(contains({ status: "fail", message: regex(/^The provider's RSA keys are 1024, 2047 bits; luci-sso requires at least 2048\. Keys: /) }),
			jwks([ WEAK_1024_JWK, { kty: "RSA", kid: "k2047", n: N_2047, e: "AQAB" }, { ...WEAK_1024_JWK, kid: "again" } ]));
	});

	it('passes a 2048-bit RSA key, and warns when a shorter one comes first', () => {
		assert.match(contains({ status: "pass" }), jwks([ f.MOCK_JWK ]));
		assert.match(contains({ status: "warn" }), jwks([ WEAK_1024_JWK, f.MOCK_JWK ]));
	});

	it('fails an RSA key whose public exponent is not 65537, even 65537 with a leading zero byte', () => {
		for (let k in [ E3_JWK, { ...f.MOCK_JWK, e: "AAEAAQ" }, { ...f.MOCK_JWK, e: "Aw" } ])
			assert.match(contains({ status: "fail", message: regex(/^The provider's RSA key has a public exponent other than 65537 \(AQAB\), the only one luci-sso accepts\. Keys: /) }), jwks([ k ]), k.e);
	});

	it('fails an EC key on another curve, labelled as it is or as P-256', () => {
		assert.match(contains({ status: "fail", message: regex(/^No key a login would pick can verify ID tokens/) }), jwks([ P384_JWK ]));
		assert.match(contains({ status: "fail", message: regex(/^No key a login would pick can verify ID tokens/) }), jwks([ { ...P384_JWK, crv: "P-256" } ]));
	});

	it('agrees with the real native module, key by key: the test passes exactly the keys a login verifies with', () => {
		// A login turns the JWK into a PEM and verifies an RS256 signature
		// with it (oidc.verify_id_token, crypto.jwt_verify).
		let login_verifies = (jwk, privkey) => {
			let pem = crypto.jwk_to_pem(native, jwk);
			if (!pem.ok || !privkey) return false;
			let parts = split(h.generate_id_token({ sub: "x" }, privkey, "RS256"), ".");
			return native.verify_rs256(`${parts[0]}.${parts[1]}`, encoding.b64url_decode(parts[2]).data, pem.data) === true;
		};
		for (let c in [
			[ "2048 bits, AQAB", f.MOCK_JWK, f.MOCK_PRIVKEY ],
			[ "1024 bits, AQAB", WEAK_1024_JWK, WEAK_1024_PRIVKEY ],
			[ "2048 bits, e=3", E3_JWK, null ],
			[ "2048 bits, AAEAAQ", { ...f.MOCK_JWK, e: "AAEAAQ" }, f.MOCK_PRIVKEY ],
		]) {
			let expected = login_verifies(c[1], c[2]);
			assert.match(expected ? "pass" : "fail", jwks([ c[1] ]).status, c[0]);
		}
		assert.match(true, login_verifies(f.MOCK_JWK, f.MOCK_PRIVKEY), "the control: a 2048-bit key verifies");
		assert.match(false, login_verifies(WEAK_1024_JWK, WEAK_1024_PRIVKEY), "native refuses the 1024-bit key at login");
	});
});

describe('connection: check — redirect URI', () => {
	it('fails an empty, plain-HTTP or wrong-path redirect URI', () => {
		assert.match("fail", run({ redirect_uri: "" }).checks.redirect_uri.status);
		assert.match({ status: "fail", message: "Redirect URI must start with https://." },
			run({ redirect_uri: "http://router.example.com/cgi-bin/luci-sso/callback" }).checks.redirect_uri);
		for (let bad in [ "https://router.example.com/", "https://router.example.com/cgi-bin/luci-sso/callback/", "https://router.example.com/cgi-bin/luci-sso/callback?x=1", "https://router.example.com/cgi-bin/luci/callback" ])
			assert.match({ status: "fail", message: "Redirect URI must end in /cgi-bin/luci-sso/callback." }, run({ redirect_uri: bad }).checks.redirect_uri, bad);
	});

	it('passes an HTTPS redirect URI ending in the callback path, whatever the host and port', () => {
		for (let good in [ REDIRECT, "https://192.168.1.1:8443/cgi-bin/luci-sso/callback", "HTTPS://Router/cgi-bin/luci-sso/callback" ])
			assert.match("pass", run({ redirect_uri: good }).checks.redirect_uri.status, good);
	});
});

describe('connection: check — client credentials', () => {
	const TOKEN = f.MOCK_DISCOVERY.token_endpoint;
	let creds = (reply) => run(null, idp({ [TOKEN]: reply })).checks.client_credentials;

	it('passes on invalid_grant: the provider accepted the client and refused only the made-up code', () => {
		assert.match("pass", creds({ status: 400, body: { error: "invalid_grant" } }).status);
	});

	it('fails on invalid_client, or on HTTP 401 whatever the body', () => {
		assert.match({ status: "fail", message: "The provider rejected the Client ID or Client Secret (invalid_client). Copy both again from the provider." },
			creds({ status: 401, body: { error: "invalid_client" } }));
		assert.match(contains({ status: "fail" }), creds({ status: 400, body: { error: "invalid_client" } }));
		assert.match({ status: "fail", message: "The provider rejected the Client ID or Client Secret (HTTP 401). Copy both again from the provider." },
			creds({ status: 401, body: "" }));
	});

	it('warns on any other answer, naming it', () => {
		assert.match({ status: "warn", message: "Couldn't determine whether the Client ID and Client Secret are right: the provider answered unauthorized_client." },
			creds({ status: 400, body: { error: "unauthorized_client" } }));
		assert.match({ status: "warn", message: "Couldn't determine whether the Client ID and Client Secret are right: the provider answered HTTP 500." },
			creds({ status: 500, body: "oops" }));
		assert.match(contains({ status: "warn" }), creds({ status: 200, body: { access_token: "x" } }));
	});

	it('fails when the token endpoint cannot be reached', () => {
		assert.match({ status: "fail", message: `No answer from ${TOKEN} within 5 seconds.` }, creds({ error: "TIMED_OUT" }));
	});

	it('fails without a client ID or secret, and sends nothing', () => {
		for (let p in [ { client_id: "" }, { client_secret: "" } ]) {
			let r = run(p);
			assert.match({ status: "fail", message: "Client ID and Client Secret are both required." }, r.checks.client_credentials);
			assert.match([], r.posts);
		}
	});

	it('treats missing or non-string parameters as empty', () => {
		let r;
		with_context({ fs: { data: {} }, http_client: { data: idp() }, clock: { data: { now: 1516239022 } } }, (deps) => {
			r = connection.check(deps, { issuer_url: 42 });
		});
		assert.match(contains({ ok: true }), r);
		assert.match("fail", r.data.checks[0].status);
		assert.match("fail", r.data.checks[5].status, "redirect_uri");
	});
});

// ─── run: what the test program runs ─────────────────────────────────────────

// A reply's checks as { id: status }.
function reduce_status(checks) {
	let out = {};
	for (let c in checks) out[c.id] = c.status;
	return out;
}

// Runs connection.run on `input` against the mock provider; returns its reply, parsed.
function run_text(input) {
	let out = null;
	with_context({
		fs:          { data: {} },
		http_client: { data: idp() },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		deps.log = () => null;
		let text = connection.run(deps, input);
		assert.match("string", type(text));
		assert.match(true, length(text) <= connection.MAX_REPLY);
		out = json(text);
	});
	return out;
}

describe('connection: run', () => {
	it('runs the checks on the parameters as JSON, and replies with them as JSON', () => {
		let reply = run_text(sprintf("%J", PARAMS));
		assert.match(true, reply.done);
		assert.match(ALL_PASS, reduce_status(reply.checks));
	});

	it('never puts the client secret in the reply', () => {
		for (let p in [ PARAMS, { ...PARAMS, client_secret: SECRET + "x" }, { ...PARAMS, issuer_url: "http://" + SECRET } ])
			assert.match(-1, index(sprintf("%J", run_text(sprintf("%J", p))), SECRET));
	});

	it('fails the test, without a crash, on input that is not a JSON object', () => {
		for (let input in [ null, "", "not json", "[1,2]", "42", "\"text\"", "{" ])
			assert.match({ done: true, error: "TEST_FAILED", message: "the test received no settings" }, run_text(input), `${input}`);
	});
});
