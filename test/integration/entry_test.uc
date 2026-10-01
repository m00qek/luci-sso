import { describe, it, assert, truthy } from 'utest';
import * as entry from 'luci_sso.entry';
import * as session from 'luci_sso.session';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context, rpcd_logins } from 'context';
import * as f from 'fixtures.oidc';
import * as h from 'lib.helpers';

// Integration bucket — enter at entry.run(deps, web_deps), the CGI composition
// root. Real web + config + router run against a deps graph built by
// with_context (faked system boundary). Asserts the pipeline glue that only
// entry.run owns: request-failure rendering, the SSO_DISABLED ?action=enabled
// escape hatch (W2), config-ok routing, and the top-level crash handler. Deep
// routing/flow behaviour lives in router_test / handshake_test.

const NOW = 1516239022;

// A valid, enabled luci-sso UCI configuration (mirrors config_test's fixture).
const ENABLED_UCI = {
	default: {
		".type": "oidc", enabled: "1",
		issuer_url: "https://idp.com", client_id: "c1", client_secret: "s1",
		redirect_uri: "https://r1/callback", clock_tolerance: "300",
	},
	r1: { ".type": "role", email: "admin@test.com" },
};

// A present-but-disabled config: config.load resolves this to SSO_DISABLED. The
// section must exist so the strict uci proxy resolves the `enabled` lookup to
// "0" rather than dying on an unmodelled path.
const DISABLED_UCI = { default: { ".type": "oidc", enabled: "0" } };

// Capture web_deps: records everything written to stdout and every log line.
// getenv is a plain CGI accessor (not a proxied module); `getenv_dies` forces a
// throw to exercise the crash handler.
function web_deps(env_map, opts) {
	let buf  = '';
	let logs = [];
	return {
		getenv: (opts && opts.getenv_dies)
			? (k) => die("boom")
			: (k) => (env_map && env_map[k] != null) ? env_map[k] : null,
		stdout: { write: (s) => { buf += s; }, flush: () => {} },
		log:    (l, m) => push(logs, [l, m]),
		out:    () => buf,
		logs:   () => logs,
	};
}

describe('entry: run', () => {
	it('renders a sanitised error with the request status when parsing fails', () => {
		// An over-length PATH_INFO makes web.request fail with INPUT_TOO_LARGE (431).
		let big = '';
		for (let i = 0; i < 16385; i++) big += 'a';
		let wd = web_deps({ PATH_INFO: big });

		with_context({ fs: { data: {} }, uci: { data: {} }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), "431") >= 0, "should use the request-failure status (431)");
		assert.match(truthy(), index(wd.out(), "<p>The request contained too much data.") >= 0, "should render the sanitised error body");
	});

	it('serves ?action=enabled even when SSO is disabled (W2 escape hatch)', () => {
		let wd = web_deps({ PATH_INFO: "/", QUERY_STRING: "action=enabled" });

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": DISABLED_UCI } }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), '{"enabled": false}') >= 0, "should return the enabled probe, not the disabled error");
		assert.match(truthy(), index(wd.out(), "200") >= 0, "escape hatch responds 200");
	});

	it('renders SSO_DISABLED (500) for a normal path when config is disabled', () => {
		let wd = web_deps({ PATH_INFO: "/callback" });

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": DISABLED_UCI } }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), "500") >= 0, "disabled non-probe path is a 500");
		assert.match(truthy(), index(wd.out(), "<p>Single sign-on is not enabled on this router.") >= 0, "renders the SSO_DISABLED page");
	});

	it('logs which option is wrong when the configuration is rejected', () => {
		// clock_tolerance out of range: config.load fails with CONFIG_ERROR and a
		// detail naming the option. The detail must reach deps.log (syslog), and
		// neither the detail nor any UCI value may reach the page.
		let bad = { ...ENABLED_UCI, default: { ...ENABLED_UCI.default, clock_tolerance: "99999" } };
		let wd = web_deps({ PATH_INFO: "/" });
		let logged = [];

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": bad } }, clock: { data: { now: NOW } } }, (deps) => {
			deps.log = (l, m) => push(logged, [l, m]);
			entry.run(deps, wd);
		});

		let line = null;
		for (let l in logged) if (index(l[1], "Configuration rejected:") == 0) line = l;
		assert.match(["error", "Configuration rejected: clock_tolerance must be between 0 and 3600 seconds"], line);
		assert.match(-1, index(wd.out(), "clock_tolerance"), "the detail stays out of the page");
		assert.match(-1, index(wd.out(), "99999"), "the value stays out of the page");
	});

	it('sends Retry-After with a 429', () => {
		// Eleven login initiations from one client: the eleventh is refused.
		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": ENABLED_UCI } },
		               http_client: { data: { "https://idp.com/.well-known/openid-configuration": { status: 503, body: "" } } },
		               clock: { data: { now: NOW } } }, (deps) => {
			let wd;
			for (let i = 0; i < 11; i++) {
				wd = web_deps({ PATH_INFO: "/", REMOTE_ADDR: "203.0.113.5" });
				entry.run(deps, wd);
			}
			assert.match(truthy(), index(wd.out(), "Status: 429 Too Many Requests") >= 0);
			assert.match(truthy(), match(wd.out(), /\nRetry-After: [0-9]+\n/) != null, "Retry-After header present");
		});
	});

	it('exempts the address in trusted_proxy from the per-client limits, and only that one', () => {
		// Login starts through entry.run with trusted_proxy read from UCI. The
		// IdP is down, so each start fails with 502 after the rate limit.
		let uci = { ...ENABLED_UCI, default: { ...ENABLED_UCI.default, trusted_proxy: [ "127.0.0.1" ] } };
		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": uci } },
		               http_client: { data: { "https://idp.com/.well-known/openid-configuration": { status: 503, body: "" } } },
		               clock: { data: { now: NOW } } }, (deps) => {
			let from = (addr) => {
				let wd = web_deps({ PATH_INFO: "/", REMOTE_ADDR: addr });
				entry.run(deps, wd);
				return wd.out();
			};
			for (let i = 0; i < 15; i++)
				assert.match(-1, index(from("127.0.0.1"), "Status: 429"), `trusted request ${i}`);
			for (let i = 0; i < 10; i++) from("192.0.2.50");
			assert.match(truthy(), index(from("192.0.2.50"), "Status: 429") >= 0, "another address is limited");
		});
	});

	it('refuses a trusted_proxy entry that is not an address, with a 500 and the option named', () => {
		let uci = { ...ENABLED_UCI, default: { ...ENABLED_UCI.default, trusted_proxy: [ "localhost" ] } };
		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": uci } }, clock: { data: { now: NOW } } }, (deps) => {
			let logs = [];
			deps.log = (l, m) => push(logs, [ l, m ]);
			let wd = web_deps({ PATH_INFO: "/", REMOTE_ADDR: "127.0.0.1" });
			entry.run(deps, wd);
			assert.match(truthy(), index(wd.out(), "Status: 500") >= 0);
			assert.match(1, length(filter(logs, (l) => l[1] == "Configuration rejected: trusted_proxy entries must be IP addresses or CIDR ranges")));
		});
	});

	it('loads config and routes when SSO is enabled', () => {
		// config.load succeeds → router.handle runs against the live config; the
		// action=enabled short-circuit reflects the loaded (enabled) state.
		let wd = web_deps({ PATH_INFO: "/", QUERY_STRING: "action=enabled" });

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": ENABLED_UCI } }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), '{"enabled": true}') >= 0, "config-ok path routes to the live enabled check");
		assert.match(truthy(), index(wd.out(), "200") >= 0);
	});

	it('renders a 500 crash page and logs when the pipeline throws', () => {
		let wd = web_deps(null, { getenv_dies: true });

		with_context({ fs: { data: {} }, uci: { data: {} }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), "500 Internal Server Error") >= 0, "catch-all renders a 500");
		let crashed = false;
		for (let l in wd.logs()) if (index(l[1], "Router crash") >= 0) crashed = true;
		assert.match(truthy(), crashed, "catch-all logs the crash");
	});
});

describe('entry: run — IdP error on the callback', () => {
	it('logs the IdP error and description sanitised, and never renders them', () => {
		let evil = "access_denied\r\n<script>alert(1)</script>";
		let desc = "User\ncancelled <b>login</b>";
		let qs = `error=${replace(evil, /[\r\n<>\/()]/g, (c) => sprintf("%%%02X", ord(c)))}&error_description=${replace(desc, /[\r\n<>\/ ]/g, (c) => sprintf("%%%02X", ord(c)))}`;
		let wd = web_deps({ PATH_INFO: "/callback", QUERY_STRING: qs, REMOTE_ADDR: "192.0.2.10" });

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": ENABLED_UCI } }, clock: { data: { now: NOW } } }, (deps) => {
			let logs = [];
			deps.log = (l, m) => push(logs, m);
			entry.run(deps, wd);
			let line = filter(logs, (m) => index(m, "IDP_ERROR: the IdP returned error=") == 0);
			assert.match(1, length(line), sprintf("%J", logs));
			assert.match("IDP_ERROR: the IdP returned error=access_denied??<script>alert(1)</script> (User?cancelled <b>login</b>)", line[0]);
		});

		let out = wd.out();
		assert.match(truthy(), index(out, "400") >= 0, "IDP_ERROR responds 400");
		assert.match(-1, index(out, "alert(1)"), "the IdP's error value must never reach the page");
		assert.match(-1, index(out, "cancelled"), "the IdP's error_description must never reach the page");
	});
});

describe('entry: run — shipped config without redirect_uri', () => {
	it('enabling SSO without setting redirect_uri logs which option is missing', () => {
		// The shipped /etc/config/luci-sso leaves redirect_uri unset so the
		// settings page can suggest the browser's host. Enabled as-is, it must
		// fail with a reason that names the option.
		let shipped = { ...ENABLED_UCI, default: { ...ENABLED_UCI.default } };
		delete shipped.default.redirect_uri;
		let wd = web_deps({ PATH_INFO: "/" });
		let logged = [];

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": shipped } }, clock: { data: { now: NOW } } }, (deps) => {
			deps.log = (l, m) => push(logged, m);
			entry.run(deps, wd);
		});

		assert.match(1, length(filter(logged, (m) => m == "Configuration rejected: redirect_uri is mandatory and must use HTTPS")), sprintf("%J", logged));
		assert.match(truthy(), index(wd.out(), "500") >= 0);
	});

	it('the shipped, disabled config still answers the probe with enabled=false', () => {
		let shipped_disabled = { default: { ".type": "oidc", enabled: "0", issuer_url: "https://accounts.google.com",
			client_id: "REPLACE_ME", client_secret: "REPLACE_ME", scope: "openid profile email", clock_tolerance: "60" } };
		let wd = web_deps({ PATH_INFO: "/", QUERY_STRING: "action=enabled" });

		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": shipped_disabled } }, clock: { data: { now: NOW } } }, (deps) => {
			entry.run(deps, wd);
		});

		assert.match(truthy(), index(wd.out(), '{"enabled": false}') >= 0);
	});
});


describe('entry: run — IdP back-channel failures render 502 Bad Gateway', () => {
	const DISC_URL = "https://idp.com/.well-known/openid-configuration";
	const DISC_DOC = {
		issuer: "https://idp.com",
		authorization_endpoint: "https://idp.com/auth",
		token_endpoint: "https://idp.com/token",
		jwks_uri: "https://idp.com/jwks"
	};

	// Drives one CGI request through entry.run. For the callback, a real
	// handshake is seeded first so the request passes the browser-side checks
	// and fails only at the IdP. Returns { out, logs }, logs from both deps.log
	// (the module that called the IdP) and web_deps.log (the `[status]` line).
	function run_request(path, http) {
		let logs = [];
		let out;
		with_context({ fs: { data: {} }, uci: { data: { "luci-sso": ENABLED_UCI } },
		               http_client: { data: http }, clock: { data: { now: NOW } } }, (deps) => {
			deps.log = (l, m) => push(logs, m);
			let env = { PATH_INFO: path, REMOTE_ADDR: "192.0.2.20" };
			if (path == "/callback") {
				let hs = session.create_state(deps, 0).data;
				env.QUERY_STRING = `code=authcode&state=${hs.state}`;
				env.HTTP_COOKIE = `__Host-luci_sso_state=${hs.token}`;
			}
			let wd = web_deps(env);
			wd.log = (l, m) => push(logs, m);
			entry.run(deps, wd);
			out = wd.out();
		});
		return { out, logs };
	}

	function assert_502(r, code, upstream_line) {
		assert.match(truthy(), index(r.out, "Status: 502 Bad Gateway\n") >= 0, r.out);
		assert.match(1, length(filter(r.logs, (m) => m == `[502] ${code}`)), sprintf("%J", r.logs));
		if (upstream_line)
			assert.match(1, length(filter(r.logs, (m) => index(m, upstream_line) == 0)), sprintf("%J", r.logs));
	}

	it('a rejected client secret (token endpoint 401) renders 502 and logs the 401', () => {
		let r = run_request("/callback", {
			[DISC_URL]: { status: 200, body: DISC_DOC },
			"https://idp.com/token": { status: 401, body: { error: "invalid_client" } }
		});
		assert_502(r, "TOKEN_EXCHANGE_FAILED", "Token exchange HTTP 401 [session_id: ");
		assert.match(-1, index(r.out, "401"), "the IdP status never reaches the browser");
	});

	it('an IdP 502 at the token endpoint renders 502, not 500', () => {
		let r = run_request("/callback", {
			[DISC_URL]: { status: 200, body: DISC_DOC },
			"https://idp.com/token": { status: 502, body: "" }
		});
		assert_502(r, "TOKEN_EXCHANGE_FAILED", "Token exchange HTTP 502 [session_id: ");
	});

	it('invalid_grant renders 502 and logs the upstream status', () => {
		let r = run_request("/callback", {
			[DISC_URL]: { status: 200, body: DISC_DOC },
			"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } }
		});
		assert_502(r, "OIDC_INVALID_GRANT", "Token exchange failed (invalid_grant, HTTP 400) [session_id: ");
		assert.match(truthy(), index(r.out, "<p>This sign-in attempt expired or was already used. Please try signing in again.") >= 0);
	});

	it('an unreachable token endpoint renders 502 and logs the cause', () => {
		let r = run_request("/callback", {
			[DISC_URL]: { status: 200, body: DISC_DOC },
			"https://idp.com/token": { error: "CONNECTION_FAILED" }
		});
		assert_502(r, "TOKEN_ENDPOINT_NETWORK_ERROR", "Token exchange network error [session_id: ");
	});

	it('a JWK Set endpoint 503 renders 502 and logs the 503', () => {
		let r = run_request("/callback", {
			[DISC_URL]: { status: 200, body: DISC_DOC },
			"https://idp.com/token": { status: 200, body: { id_token: "a.b.c", access_token: "at" } },
			"https://idp.com/jwks": { status: 503, body: {} }
		});
		assert_502(r, "JWKS_FETCH_FAILED", "JWKS fetch HTTP 503 from [id: ");
	});

	it('a discovery 404 at login renders 502 and logs the 404', () => {
		let r = run_request("/", { [DISC_URL]: { status: 404, body: {} } });
		assert_502(r, "OIDC_DISCOVERY_FAILED", "Discovery fetch HTTP 404 from [id: ");
	});
});

describe('entry: run — a refused user sees their own sub', () => {
	// A full callback through the CGI pipeline for a user whose sub, email and
	// groups match no role. The ID token is genuinely signed, and its sub is
	// markup, so the page must escape it.
	function refused_login(sub) {
		let wd;
		let logs = [];
		let uci = { ...ENABLED_UCI, default: { ...ENABLED_UCI.default, issuer_url: f.MOCK_CONFIG.issuer_url, client_id: f.MOCK_CONFIG.client_id } };
		with_context({
			fs:   { data: {} },
			uci:  { data: { "luci-sso": uci, ...rpcd_logins({ r1: { read: [ "*" ] } }) } },
			ubus: { data: {} },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-refused";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, sub, email: "stranger@example.com", nonce: "test-nonce", at_hash };
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token: h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256") }) } };
					}
				}
			},
			clock: { data: { now: NOW } }
		}, (deps) => {
			deps.log = (l, m) => push(logs, m);
			let hs = session.create_state(deps, 300).data;
			let path = "/var/run/luci-sso/handshake_" + hs.token + ".json";
			let raw = encoding.safe_json(deps.fs.readfile(path)).data;
			raw.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw));
			wd = web_deps({ PATH_INFO: "/callback", QUERY_STRING: `code=c&state=${raw.state}`,
				HTTP_COOKIE: `__Host-luci_sso_state=${hs.token}`, REMOTE_ADDR: "192.0.2.20" });
			entry.run(deps, wd);
		});
		return { out: wd.out(), logs };
	}

	it('renders USER_NOT_AUTHORIZED (403) with the escaped sub and a line saying to give it to the administrator', () => {
		let r = refused_login(`Ab<b>"1"</b>&'`);
		assert.match(truthy(), index(r.out, "Status: 403 Forbidden\n") >= 0, r.out);
		assert.match(truthy(), index(r.out, "<p>Your account is not allowed to manage this router.") >= 0, r.out);
		assert.match(truthy(), index(r.out,
			"<p>If you ask for access, give your administrator this account identifier: <code>Ab&lt;b&gt;&quot;1&quot;&lt;/b&gt;&amp;&#39;</code></p>") >= 0, r.out);
		assert.match(-1, index(r.out, "<b>"), "no markup from the sub");
	});

	it('shows nothing else about the user, and logs only the hashed sub', () => {
		let r = refused_login("248289761001");
		assert.match(truthy(), index(r.out, "<code>248289761001</code>") >= 0, r.out);
		assert.match(-1, index(r.out, "stranger@example.com"), "not the email");
		assert.match(0, length(filter(r.logs, (m) => index(m, "248289761001") >= 0)), sprintf("%J", r.logs));
		assert.match(1, length(filter(r.logs, (m) => match(m, /^User \[sub_id: [^\]]+\] matched no roles/))), sprintf("%J", r.logs));
	});
});
