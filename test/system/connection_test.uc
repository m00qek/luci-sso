import { describe, it, assert, contains } from 'utest';
import * as uci from 'uci';
import * as fs from 'fs';
import * as r from 'lib.rpcd';

// System bucket: the luci-sso ubus object's connection test, in the
// container's REAL rpcd, against the devenv's mock IdP over real HTTPS. The
// test runs in a child of rpcd (uloop.task); these tests pin down that it
// reports the checks, that rpcd keeps answering meanwhile, and that it
// changes nothing on the router.

// The provider settings the devenv configured the router with.
function devenv_params(over) {
	let c = uci.cursor();
	return {
		issuer_url: c.get("luci-sso", "default", "issuer_url"),
		internal_issuer_url: c.get("luci-sso", "default", "internal_issuer_url") || "",
		client_id: c.get("luci-sso", "default", "client_id"),
		client_secret: c.get("luci-sso", "default", "client_secret"),
		redirect_uri: c.get("luci-sso", "default", "redirect_uri"),
		...(over || {})
	};
}

function call(conn, method, args) {
	let res = conn.call("luci-sso", method, args || {});
	return (res == null) ? { ubus_error: conn.error() } : res;
}

// Starts a test and waits for its result (at most 30 s).
function run_test(conn, params) {
	let started = call(conn, "test_connection", params);
	assert.match("string", type(started.job), sprintf("%J", started));
	for (let i = 0; i < 300; i++) {
		let res = call(conn, "test_connection_result", { job: started.job });
		if (res.done || res.error) return { job: started.job, reply: res };
		sleep(100);
	}
	die("the connection test did not finish within 30 s");
}

function statuses(reply) {
	let out = {};
	for (let c in reply.checks) out[c.id] = c.status;
	return out;
}

// The cache files, with their modification times.
function cache_state() {
	let out = {};
	for (let f in (fs.lsdir("/var/run/luci-sso") || []))
		if (match(f, /^oidc-/)) out[f] = fs.stat(`/var/run/luci-sso/${f}`).mtime;
	return out;
}

describe('system: luci-sso ubus object — test_connection', () => {
	it('passes every check against the devenv IdP with the devenv settings', () => {
		let conn = r.connect();
		let res = run_test(conn, devenv_params());
		assert.match({
			issuer_https: "pass", discovery: "pass", issuer_match: "pass", endpoints: "pass",
			jwks: "pass", redirect_uri: "pass", client_credentials: "pass"
		}, statuses(res.reply), sprintf("%J", res.reply));
	});

	it('never returns the client secret', () => {
		let conn = r.connect();
		let secret = devenv_params().client_secret;
		for (let p in [ {}, { client_secret: secret + "-wrong" }, { issuer_url: devenv_params().issuer_url + "/" } ]) {
			let res = run_test(conn, devenv_params(p));
			assert.match(-1, index(sprintf("%J", res.reply), secret), sprintf("%J", p));
		}
	});

	it('fails the credentials check for a wrong secret, and names invalid_client', () => {
		let conn = r.connect();
		let res = run_test(conn, devenv_params({ client_secret: "wrong" }));
		let c = filter(res.reply.checks, (x) => x.id == "client_credentials")[0];
		assert.match("fail", c.status);
		assert.match(true, index(c.message, "invalid_client") >= 0, c.message);
	});

	it('shows the near-miss hint for an issuer with a trailing slash', () => {
		let conn = r.connect();
		let res = run_test(conn, devenv_params({ issuer_url: devenv_params().issuer_url + "/" }));
		let c = filter(res.reply.checks, (x) => x.id == "issuer_match")[0];
		assert.match("fail", c.status);
		assert.match(true, index(c.message, "differ only in a trailing slash") >= 0, c.message);
	});

	it('writes no cache file and changes none', () => {
		let conn = r.connect();
		let before = cache_state();
		run_test(conn, devenv_params());
		assert.match(before, cache_state());
	});

	it('runs one test at a time, while rpcd keeps answering', () => {
		let conn = r.connect();
		let first = call(conn, "test_connection", devenv_params());
		assert.match("string", type(first.job));
		assert.match({ error: "BUSY", message: "a connection test is already running" }, call(conn, "test_connection", devenv_params()));
		assert.match("array", type(call(conn, "list_roles").roles), "rpcd answers while the test runs");
		for (let i = 0; i < 300; i++) {
			if (call(conn, "test_connection_result", { job: first.job }).done) break;
			sleep(100);
		}
		let second = call(conn, "test_connection", devenv_params());
		assert.match("string", type(second.job), "a new test starts once the first is done");
		assert.match(contains({ error: "NOT_FOUND" }), call(conn, "test_connection_result", { job: first.job }), "only the latest is kept");
		for (let i = 0; i < 300; i++) {
			if (call(conn, "test_connection_result", { job: second.job }).done) break;
			sleep(100);
		}
	});

	it('answers NOT_FOUND for an unknown job, and rpcd refuses arguments of the wrong type', () => {
		let conn = r.connect();
		assert.match(contains({ error: "NOT_FOUND" }), call(conn, "test_connection_result", { job: "nope" }));
		assert.match(true, index(call(conn, "test_connection", { issuer_url: 42 }).ubus_error, "Invalid argument") == 0);
	});
});
