import { describe, it, assert, truthy } from 'utest';
import * as entry from 'luci_sso.entry';
import { with_context } from 'context';

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
	r1: { ".type": "role", email: "admin@test.com", read: ["*"], write: ["*"] },
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
		assert.match(truthy(), index(wd.out(), "Error:") >= 0, "should render the sanitised error body");
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
		assert.match(truthy(), index(wd.out(), "Error:") >= 0);
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
