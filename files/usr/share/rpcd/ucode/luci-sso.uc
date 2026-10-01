// SPDX-License-Identifier: MIT
//
// rpcd ucode plugin: the `luci-sso` ubus object.
//
// Manages the rpcd login entries that hold the permissions of luci-sso's
// roles. Each role has exactly one entry in /etc/config/rpcd:
//
//   config login 'luci_sso_<role>'
//   	option username 'sso:<role>'
//   	list read '<access group or pattern>'
//   	list write '<access group or pattern>'
//
// and never a password option: rpcd's password login skips an entry without
// one, so these entries can rebuild SSO sessions on an rpcd reload but can
// never be used to log in. An EMPTY password would accept any password, so
// this plugin never writes the option at all, and removes one it finds.
//
// The naming, the checks and the lists' rules live in luci_sso.rpcd_login,
// which the login path shares. In particular, set_role stores a read list that
// grants the `unauthenticated` access group, which LuCI needs on every page:
// it appends the group unless the list grants it already (by name or through
// a pattern such as '*'), and refuses a list that denies it. The reply and
// list_roles show the lists as stored. A role whose lists grant nothing else
// is valid: its users can log in but see nothing.
//
// The settings page changes permissions only through this object, so its ACL
// needs no UCI write access to the whole `rpcd` configuration. Every write
// touches only sections named `luci_sso_*`.
//
// Methods. rpcd itself refuses an argument of the wrong type, or one not
// listed, with UBUS_STATUS_INVALID_ARGUMENT; every other error is a reply of
// the form { error: "<CODE>", message: "<text>" }:
//
//   list_roles {}                            -> { roles: [ { name, read, write } ],
//                                                reload_pending }
//   set_role { name, read, write }           -> { role: { name, read, write } },
//                                               the lists as stored
//   delete_role { name }                     -> { result: true }
//   list_acl_groups {}                       -> { groups: [ "<access group>" ] },
//                                               the top-level keys of every
//                                               /usr/share/rpcd/acl.d/*.json,
//                                               sorted, each once; the settings
//                                               page offers them as suggestions
//   test_connection { issuer_url, internal_issuer_url, client_id,
//                     client_secret, redirect_uri }
//                                            -> { job: "<id>" }
//   test_connection_result { job }           -> { done: false }, or
//                                               { done: true, checks: [ { id, status, message } ] }
//
// Error codes: INVALID_NAME, INVALID_LIST, NOT_FOUND, COMMIT_FAILED, BUSY,
// TIMEOUT, TEST_FAILED.
//
// Connection test: test_connection checks the settings page's provider
// values, saved or not, with luci_sso.connection, which runs the login's own
// discovery, JWK Set and token-request code without touching any cache. The
// checks make up to three HTTPS requests to the IdP, which would block rpcd
// if they ran here, and uclient's event loop cannot run nested inside rpcd's:
// ending it would end rpcd's own loop too. So they run in a child process
// (uloop.task, a fork of rpcd), and rpcd stays responsive meanwhile. rpcd on
// OpenWrt 24.10 cannot defer a ucode plugin's reply, so test_connection
// answers at once with a job ID, and the page asks test_connection_result
// until the result is there. One test runs at a time (BUSY otherwise); only
// the latest is kept, in memory, never on disk. A test that has not finished
// after TEST_TIMEOUT_MS is killed and reported as TIMEOUT; each HTTP request
// already gives up after connection.HTTP_TIMEOUT_MS. The client secret is
// passed to the child in memory only, never logged and never part of a
// reply.
//
// Order: list_roles returns the entries in the order of /etc/config/rpcd,
// which means nothing: rpcd matches login entries by exact username, and
// luci-sso picks a user's role in the order of /etc/config/luci-sso, which the
// settings page edits through UCI.
//
// Reload: rpcd rebuilds each session's ACLs from the login entry matching its
// username only when it reloads (SIGHUP: it saves its sessions, re-executes
// itself and restores them). After a successful write this plugin, which runs
// inside rpcd, schedules a SIGHUP to its own process on rpcd's event loop, one
// second after the reply. That is what `/etc/init.d/rpcd reload` does through
// procd, but it also works where rpcd is not run by procd. Writes that arrive
// while a reload is pending share it: the reload reads the configuration as
// it is when it runs, and a second signal during rpcd's restart could stop it.
// list_roles reports reload_pending: true from a write until rpcd has
// re-executed itself (the new process starts with it false), so a caller can
// wait for the new rights to be in force.

"use strict";

import { cursor } from 'uci';
import { mkdir, readlink, readfile, lsdir } from 'fs';
import * as uloop from 'uloop';
import * as rpcd_login from 'luci_sso.rpcd_login';
import { uci_list } from 'luci_sso.config';
import * as connection from 'luci_sso.connection';
import { create_probe } from 'luci_sso.deps';

const CONFIG = rpcd_login.CONFIG;
const SECTION_PREFIX = rpcd_login.SECTION_PREFIX;

// A private UCI delta directory: a commit here writes only this plugin's own
// changes, never changes to rpcd that someone else staged and did not commit.
const RUN_DIR = "/var/run/luci-sso";
const DELTA_DIR = "/var/run/luci-sso/rpcd-uci";

const RELOAD_DELAY_MS = 1000;

// Where LuCI packages define their access groups.
const ACL_DIR = "/usr/share/rpcd/acl.d";

// Above the three requests' 5 s timeouts. Each poll of the result answers
// at once, so LuCI's call timeout never applies to the test itself.
const TEST_TIMEOUT_MS = 25000;

let reload_timer = null;

// The latest connection test: { id, task, timer, reply }, reply null while
// it runs.
let conn_test = null;

function fail(code, message) {
	return { error: code, message };
}

function open_cursor() {
	mkdir(RUN_DIR, 0700);
	mkdir(DELTA_DIR, 0700);
	let uci = cursor("/etc/config", DELTA_DIR);
	uci.revert(CONFIG);
	return uci;
}

// A failed Result from luci_sso.rpcd_login as a reply.
function refused(res) {
	return fail(res.error, res.details);
}

// The luci_sso_* login entries in config order.
function sso_entries(uci) {
	let out = [];
	uci.foreach(CONFIG, null, (s) => {
		let name = substr(s[".name"], length(SECTION_PREFIX));
		if (s[".type"] != "login" || substr(s[".name"], 0, length(SECTION_PREFIX)) != SECTION_PREFIX)
			return;
		if (!rpcd_login.check_name(name).ok)
			return;
		push(out, { name, read: uci_list(s.read), write: uci_list(s.write) });
	});
	return out;
}

function schedule_reload() {
	if (reload_timer)
		return;
	let pid = int(readlink("/proc/self"));
	reload_timer = uloop.timer(RELOAD_DELAY_MS, () => {
		// Left set on success: rpcd is about to re-execute itself, and calls
		// it still answers until then must see the reload as pending.
		if (system([ "/bin/kill", "-HUP", `${pid}` ]) != 0)
			reload_timer = null;
	});
}

// A random job ID. Only the latest test is kept, so the ID just tells a stale
// poll from a current one.
function job_id() {
	let raw = readfile("/dev/urandom", 8) || "";
	let id = "";
	for (let i = 0; i < length(raw); i++)
		id += sprintf("%02x", ord(raw, i));
	return length(id) ? id : sprintf("%x", time());
}

// Called from the task's or the timer's callback. The task object is kept:
// dropping the last reference to it inside its own callback lets ucode free
// it while uloop still uses it, which crashes rpcd. It goes when the next
// test replaces this one, outside any callback; the closure holding the
// secret is released as soon as uloop has cleaned the task up.
function finish_test(t, reply) {
	if (t.reply != null)
		return;
	t.reply = reply;
	if (t.timer)
		t.timer.cancel();
}

function start_test(params) {
	let t = { id: job_id(), task: null, timer: null, reply: null };
	// Runs in the child, a fork of rpcd, whose own event loop the HTTP
	// client may start and end.
	t.task = uloop.task(function() {
		let res = connection.check(create_probe(connection.HTTP_TIMEOUT_MS), params);
		return res.ok ? { done: true, checks: res.data.checks } : { done: true, error: "TEST_FAILED", message: `${res.error}` };
	}, function(msg) {
		finish_test(t, (type(msg) == "object") ? msg : { done: true, error: "TEST_FAILED", message: "the test returned no result" });
	}, function() {
		// Never called: the task asks for no input. Passing it makes ucode
		// close the task's pipes when it ends, which it skips for a task
		// without an input callback, leaking a pipe per test.
		return null;
	});
	if (!t.task)
		return null;
	t.timer = uloop.timer(TEST_TIMEOUT_MS, () => {
		if (!t.task.finished()) t.task.kill();
		finish_test(t, { done: true, error: "TIMEOUT", message: `the test did not finish within ${TEST_TIMEOUT_MS / 1000} seconds and was stopped` });
	});
	return t;
}

function commit(uci) {
	if (!uci.commit(CONFIG))
		return fail("COMMIT_FAILED", `could not write /etc/config/${CONFIG}`);
	schedule_reload();
	return null;
}

const methods = {
	list_roles: {
		call: function() {
			let uci = open_cursor();
			return { roles: sso_entries(uci), reload_pending: reload_timer != null };
		}
	},

	set_role: {
		args: { name: "name", read: [], write: [] },
		call: function(req) {
			let a = req.args;
			let res = rpcd_login.entry(a.name, a.read, a.write);
			if (!res.ok) return refused(res);
			let e = res.data;

			let uci = open_cursor();
			rpcd_login.stage(uci, e);

			let err = commit(uci);
			if (err) return err;
			return { role: { name: e.name, read: e.read, write: e.write } };
		}
	},

	delete_role: {
		args: { name: "name" },
		call: function(req) {
			let res = rpcd_login.check_name(req.args.name);
			if (!res.ok) return refused(res);

			let uci = open_cursor();
			let section = rpcd_login.section_name(req.args.name);
			if (uci.get(CONFIG, section) == null)
				return fail("NOT_FOUND", `no rpcd login entry for role '${req.args.name}'`);

			uci.delete(CONFIG, section);
			let err = commit(uci);
			if (err) return err;
			return { result: true };
		}
	},

	list_acl_groups: {
		call: function() {
			let seen = {};
			for (let f in (lsdir(ACL_DIR) || [])) {
				if (!match(f, /\.json$/))
					continue;
				let data = null;
				try { data = json(readfile(`${ACL_DIR}/${f}`) || "null"); } catch (e) { continue; }
				if (type(data) != "object")
					continue;
				// Only names a role's list could store (rpcd_login.check_list).
				for (let k in keys(data))
					if (rpcd_login.check_list("group", [ k ]).ok && substr(k, 0, 1) != "!")
						seen[k] = true;
			}
			return { groups: sort(keys(seen)) };
		}
	},

	test_connection: {
		args: { issuer_url: "", internal_issuer_url: "", client_id: "", client_secret: "", redirect_uri: "" },
		call: function(req) {
			if (conn_test && conn_test.reply == null)
				return fail("BUSY", "a connection test is already running");
			let a = req.args;
			let params = {
				issuer_url: a.issuer_url,
				internal_issuer_url: a.internal_issuer_url,
				client_id: a.client_id,
				client_secret: a.client_secret,
				redirect_uri: a.redirect_uri
			};
			let t = start_test(params);
			if (!t)
				return fail("TEST_FAILED", "could not start the test");
			conn_test = t;
			return { job: t.id };
		}
	},

	test_connection_result: {
		args: { job: "" },
		call: function(req) {
			let t = conn_test;
			if (!t || t.id !== req.args.job)
				return fail("NOT_FOUND", "no such connection test: a newer one replaced it, or rpcd restarted");
			// A child that died without a result.
			if (t.reply == null && t.task.finished())
				finish_test(t, { done: true, error: "TEST_FAILED", message: "the test stopped without a result" });
			return (t.reply != null) ? t.reply : { done: false };
		}
	}
};

return { "luci-sso": methods };
