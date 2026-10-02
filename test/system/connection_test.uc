import { describe, it, assert, contains, regex } from 'utest';
import * as uci from 'uci';
import * as fs from 'fs';
import * as r from 'lib.rpcd';

// System bucket: the luci-sso ubus object's connection test, in the
// container's REAL rpcd, against the devenv's mock IdP over real HTTPS. The
// test runs in a program of its own, /usr/libexec/luci-sso/connection-test,
// which rpcd starts with fork and exec; these tests pin down that it reports
// the checks, that rpcd keeps answering meanwhile, that it changes nothing on
// the router, that nothing of rpcd reaches it, that an rpcd reload during a
// test leaves rpcd whole, and that the deadline really stops it.

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

// rpcd's process ID, and how many pipes it holds open.
function rpcd_state() {
	for (let pid in fs.lsdir("/proc")) {
		if (!match(pid, /^[0-9]+$/)) continue;
		let cmd = fs.readfile(`/proc/${pid}/cmdline`) || "";
		if (index(cmd, "/sbin/rpcd") != 0) continue;
		let pipes = 0;
		for (let fd in (fs.lsdir(`/proc/${pid}/fd`) || []))
			if (index(fs.readlink(`/proc/${pid}/fd/${fd}`) || "", "pipe:") == 0) pipes++;
		return { pid, pipes };
	}
	return null;
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

	it('twenty tests in a row leave rpcd running, with no more open pipes than before', () => {
		let conn = r.connect();
		let before = rpcd_state();
		for (let i = 0; i < 20; i++)
			run_test(conn, devenv_params());
		assert.match(before, rpcd_state());
	});

	it('answers NOT_FOUND for an unknown job, and rpcd refuses arguments of the wrong type', () => {
		let conn = r.connect();
		assert.match(contains({ error: "NOT_FOUND" }), call(conn, "test_connection_result", { job: "nope" }));
		assert.match(true, index(call(conn, "test_connection", { issuer_url: 42 }).ubus_error, "Invalid argument") == 0);
	});
});

// ─── The test program ────────────────────────────────────────────────────────

const HELPER = "/usr/libexec/luci-sso/connection-test";

// The mock IdP's counts of token requests to its /slow and /trickle providers.
function idp(method, path) {
	let url = devenv_params().issuer_url + path;
	let p = fs.popen(`uclient-fetch -q -O - ${method == "POST" ? "--post-data=x " : ""}'${url}'`, "r");
	let out = p.read("all");
	p.close();
	return json(out);
}

// The process IDs of running test programs.
function helper_pids() {
	let out = [];
	for (let pid in fs.lsdir("/proc")) {
		if (!match(pid, /^[0-9]+$/)) continue;
		if (index(fs.readfile(`/proc/${pid}/cmdline`) || "", HELPER) >= 0) push(out, pid);
	}
	return out;
}

// Waits up to 30 s for a test's reply.
function await_result(conn, job) {
	for (let i = 0; i < 300; i++) {
		let res = call(conn, "test_connection_result", { job });
		if (res.done || res.error) return res;
		sleep(100);
	}
	die("the connection test did not finish within 30 s");
}

// Waits up to `ms` for every test program to have exited.
function await_no_helper(ms) {
	for (let i = 0; i < ms / 100; i++) {
		if (!length(helper_pids())) return;
		sleep(100);
	}
	die(`a test program still runs after ${ms} ms`);
}

// A process's descriptors: { "<fd>": "<link target>" }.
function fds(pid) {
	let out = {};
	for (let fd in (fs.lsdir(`/proc/${pid}/fd`) || []))
		out[fd] = fs.readlink(`/proc/${pid}/fd/${fd}`);
	return out;
}

// The ubus objects rpcd registers, as `ubus list` shows them.
function objects(conn) {
	let out = {};
	for (let o in (conn.list() || [])) out[o] = true;
	return out;
}

describe('system: luci-sso ubus object — the test program', () => {
	it('inherits nothing from rpcd but standard error, and never sees the secret on its command line or in its environment', () => {
		let conn = r.connect();
		let params = devenv_params({ issuer_url: devenv_params().issuer_url + "/slow" });
		let started = call(conn, "test_connection", params);
		assert.match("string", type(started.job));
		sleep(1000);

		let pids = helper_pids();
		assert.match(1, length(pids), "one test program runs");
		let rpcd = rpcd_state().pid;
		assert.match(true, pids[0] != rpcd, "it is not rpcd");
		assert.match(true, index(fs.readfile(`/proc/${pids[0]}/status`) || "", `PPid:\t${rpcd}\n`) >= 0, "rpcd started it");

		let mine = fds(pids[0]), theirs = fds(rpcd);
		assert.match(regex(/^pipe:/), mine["0"], "standard input is a pipe");
		assert.match(regex(/^pipe:/), mine["1"], "standard output is a pipe");
		assert.match(theirs["2"], mine["2"], "standard error is rpcd's");
		let shared = {};
		for (let fd, target in theirs) shared[target] = true;
		for (let fd, target in mine)
			if (+fd > 2 && match(target, /^(socket|pipe):/))
				assert.match(false, !!shared[target], `descriptor ${fd} (${target}) is rpcd's`);
		assert.match(false, !!shared[mine["0"]], "rpcd holds no end of its standard input");

		let secret = params.client_secret;
		assert.match(-1, index(fs.readfile(`/proc/${pids[0]}/cmdline`), secret), "command line");
		let env = filter(split(fs.readfile(`/proc/${pids[0]}/environ`) || "", "\u0000"), (v) => length(v));
		assert.match([], filter(env, (v) => !match(v, /^(SHLVL|PWD)=/)), "only what the shell sets");
		assert.match(-1, index(join("\n", env), secret), "environment");

		await_result(conn, started.job);
	});

	it('an rpcd reload during a test leaves rpcd with every ubus object, and logins work', () => {
		let conn = r.connect();
		let before = objects(conn);
		for (let o in [ "session", "uci", "luci-sso" ])
			assert.match(true, !!before[o], `${o} before`);
		idp("POST", "/test-hooks/reset");

		// A test against a provider that answers each request after 3 s.
		let started = call(conn, "test_connection", devenv_params({ issuer_url: devenv_params().issuer_url + "/slow" }));
		assert.match("string", type(started.job));
		sleep(1500);

		// The reload a permission save, a package install or
		// /etc/init.d/rpcd reload makes: rpcd re-executes itself.
		let rpcd = rpcd_state().pid;
		r.await_reload(conn, () => system([ "/bin/kill", "-HUP", rpcd ]));
		assert.match(contains({ error: "NOT_FOUND" }), call(conn, "test_connection_result", { job: started.job }), "the new rpcd knows no test");

		// The test goes on to the token endpoint, which answers after 3 s,
		// and then ends.
		for (let i = 0; i < 200 && idp("GET", "/test-hooks/hits").slow_token < 1; i++)
			sleep(100);
		assert.match(1, idp("GET", "/test-hooks/hits").slow_token, "the test ran to its end");
		sleep(4500);
		await_no_helper(5000);

		assert.match(before, objects(conn), "every object is still on ubus");
		let login = conn.call("session", "login", { username: "root", password: "admin" });
		assert.match("string", type(login ? login.ubus_rpc_session : null), `password login: ${conn.error()}`);
		conn.call("session", "destroy", { ubus_rpc_session: login.ubus_rpc_session });
		assert.match("array", type(call(conn, "list_roles").roles), "the luci-sso object answers");
		let res = run_test(conn, devenv_params());
		assert.match("pass", statuses(res.reply).client_credentials, "a new test runs");
	});

	it('stops a test at its deadline: the program is killed and makes no request afterwards', () => {
		let conn = r.connect();
		idp("POST", "/test-hooks/reset");

		// A provider whose JWK Set trickles in for 40 s, past the 25 s deadline.
		let started = call(conn, "test_connection", devenv_params({ issuer_url: devenv_params().issuer_url + "/trickle" }));
		assert.match("string", type(started.job));
		let reply = null;
		for (let i = 0; i < 350 && reply == null; i++) {
			let res = call(conn, "test_connection_result", { job: started.job });
			if (res.done) reply = res;
			else sleep(100);
		}
		assert.match(contains({ done: true, error: "TIMEOUT" }), reply);

		await_no_helper(1000);
		// The token request would follow the JWK Set at once.
		sleep(5000);
		assert.match(0, idp("GET", "/test-hooks/hits").trickle_token, "no token request after the deadline");
		let next = call(conn, "test_connection", devenv_params());
		assert.match("string", type(next.job), "a new test may start");
		await_result(conn, next.job);
	});

	it('refuses settings longer than 4096 bytes as JSON, and starts no program', () => {
		let conn = r.connect();
		let long = "";
		while (length(long) < 4096) long += "x";
		assert.match({ error: "TEST_FAILED", message: "the settings are too long to test" },
			call(conn, "test_connection", devenv_params({ client_id: long })));
		assert.match([], helper_pids());
	});

	it('runs by hand: settings on standard input, the reply on standard output', () => {
		let tmp = "/tmp/luci-sso-connection-test.json";
		fs.writefile(tmp, sprintf("%J", devenv_params()));
		let p = fs.popen(`${HELPER} < ${tmp}`, "r");
		let reply = json(p.read("all"));
		p.close();
		fs.unlink(tmp);
		assert.match(contains({ done: true }), reply);
		assert.match("pass", statuses(reply).client_credentials);
	});
});

// ─── What the plugin loads ────────────────────────────────────────────────────

// Modules the rpcd plugin must not load: the crypto backend and everything
// that needs it. Each is shadowed by a module that dies when loaded.
const POISON_DIR = "/tmp/luci-sso-poison";
const POISONED = [ "native", "deps", "connection", "crypto", "oidc", "discovery" ];

function with_poison(fn) {
	fs.mkdir(POISON_DIR);
	fs.mkdir(`${POISON_DIR}/luci_sso`);
	for (let m in POISONED)
		fs.writefile(`${POISON_DIR}/luci_sso/${m}.uc`, `die("loaded luci_sso.${m}");\n`);
	let failure = null;
	try { fn(); } catch (e) { failure = e; }
	for (let m in POISONED) fs.unlink(`${POISON_DIR}/luci_sso/${m}.uc`);
	fs.rmdir(`${POISON_DIR}/luci_sso`);
	fs.rmdir(POISON_DIR);
	if (failure != null) die(failure);
}

// Runs `file` with the poisoned modules first in the search path.
function load(file) {
	let p = fs.popen(`ucode -L ${POISON_DIR} ${file} 2>&1; echo "exit=$?"`, "r");
	let out = p.read("all");
	p.close();
	return out;
}

describe('system: luci-sso ubus object — what it loads', () => {
	it('loads with uci, fs, uloop and pure ucode only: no crypto backend, no OIDC code', () => {
		with_poison(() => {
			let out = load("/usr/share/rpcd/ucode/luci-sso.uc");
			assert.match("exit=0\n", out);
			// The poison works: the test program does load them.
			let helper = load(HELPER + " </dev/null");
			assert.match(true, index(helper, `${POISON_DIR}/luci_sso/`) >= 0 && index(helper, "exit=0\n") < 0, helper);
		});
	});
});
