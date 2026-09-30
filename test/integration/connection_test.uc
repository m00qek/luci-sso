import { describe, it, assert, contains, spy } from 'utest';
import * as connection from 'luci_sso.connection';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';

// Integration bucket — enter at connection.check, the settings page's
// connection test. It runs the login's real discovery, JWK Set and token
// request code (discovery + oidc + crypto, REAL native) against a faked HTTP
// boundary, and asserts each check's pass and fail, and that it touches no
// cache and never echoes or logs the client secret.

const ISSUER = f.MOCK_CONFIG.issuer_url;
const DISC = ISSUER + "/.well-known/openid-configuration";
const SECRET = "s3cr3t-Value-!";
const REDIRECT = "https://router.example.com/cgi-bin/luci-sso/callback";

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
		assert.match(contains({ message: "The JWK Set has 1 key(s); 1 can verify ID tokens (RS256, or ES256 on P-256)." }), r.checks.jwks);
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

	it('fails a JWK Set with no key luci-sso can verify ID tokens with', () => {
		let unusable = [
			{ kty: "oct", k: "c2VjcmV0" },
			{ ...f.MOCK_JWK, use: "enc" },
			{ ...f.MOCK_JWK, alg: "RS512" },
			{ ...f.MOCK_JWK, alg: "ES256" },
			{ kty: "EC", crv: "P-384", x: "AA", y: "AA" },
			{ kty: "RSA", n: "!!", e: "AQAB" },
			"not a key",
		];
		let r = run(null, idp({ [JWKS]: { status: 200, body: { keys: unusable } } }));
		assert.match({ status: "fail", message: "The JWK Set has 7 key(s), but none luci-sso can verify ID tokens with: it needs an RS256 (RSA) or ES256 (EC P-256) signing key." }, r.checks.jwks);

		let empty = run(null, idp({ [JWKS]: { status: 200, body: { keys: [] } } }));
		assert.match("fail", empty.checks.jwks.status);
	});

	it('passes when at least one key is usable, and counts them', () => {
		let r = run(null, idp({ [JWKS]: { status: 200, body: { keys: [ { kty: "oct", k: "c2VjcmV0" }, { ...f.MOCK_JWK, alg: "RS256", use: "sig" } ] } } }));
		assert.match({ status: "pass", message: "The JWK Set has 2 key(s); 1 can verify ID tokens (RS256, or ES256 on P-256)." }, r.checks.jwks);
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
