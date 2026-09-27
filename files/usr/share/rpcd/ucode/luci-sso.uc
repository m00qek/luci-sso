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
//   set_role { name, read, write }           -> { role: { name, read, write } }
//   delete_role { name }                     -> { result: true }
//   move_role { name, index }                -> { roles: [ ... ] }
//
// Error codes: INVALID_NAME, INVALID_LIST, INVALID_INDEX, NOT_FOUND,
// COMMIT_FAILED.
//
// Order: list_roles returns the entries in the order of /etc/config/rpcd.
// move_role(name, index) moves an entry so that it becomes the index-th
// (0-based) of the luci_sso_* entries; the other entries keep their relative
// order, and sections that are not luci_sso_* keep their positions. The order
// is informational: rpcd matches login entries by exact username, and
// luci-sso picks a user's role in the order of /etc/config/luci-sso.
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
import { mkdir, readlink } from 'fs';
import * as uloop from 'uloop';

const CONFIG = "rpcd";
const SECTION_PREFIX = "luci_sso_";
const USERNAME_PREFIX = "sso:";

// Role names become part of a UCI section name, so they use its alphabet.
const NAME_MAX = 32;
const NAME_RE = /^[A-Za-z0-9_]+$/;

// Access group names and rpcd patterns (globs, "!" negations) are short.
const LIST_MAX = 128;
const ENTRY_MAX = 128;
// NUL cannot appear in a POSIX regex, so it is checked on its own.
const CONTROL_RE = regexp("[\x01-\x1f\x7f]");

// A private UCI delta directory: a commit here writes only this plugin's own
// changes, never changes to rpcd that someone else staged and did not commit.
const RUN_DIR = "/var/run/luci-sso";
const DELTA_DIR = "/var/run/luci-sso/rpcd-uci";

const RELOAD_DELAY_MS = 1000;

let reload_timer = null;

function fail(code, message) {
	return { error: code, message };
}

function to_list(v) {
	if (type(v) == "array") return v;
	return (v != null) ? [ v ] : [];
}

function open_cursor() {
	mkdir(RUN_DIR, 0700);
	mkdir(DELTA_DIR, 0700);
	let uci = cursor("/etc/config", DELTA_DIR);
	uci.revert(CONFIG);
	return uci;
}

function check_name(name) {
	if (type(name) != "string" || !length(name))
		return fail("INVALID_NAME", "name is required");
	if (length(name) > NAME_MAX)
		return fail("INVALID_NAME", `name is longer than ${NAME_MAX} characters`);
	if (!match(name, NAME_RE))
		return fail("INVALID_NAME", "name may contain only letters, digits and underscores");
	return null;
}

function check_list(label, list) {
	if (type(list) != "array")
		return fail("INVALID_LIST", `${label} must be an array of strings`);
	if (length(list) > LIST_MAX)
		return fail("INVALID_LIST", `${label} has more than ${LIST_MAX} entries`);
	for (let i = 0; i < length(list); i++) {
		let e = list[i];
		if (type(e) != "string")
			return fail("INVALID_LIST", `${label}[${i}] is not a string`);
		if (!length(e))
			return fail("INVALID_LIST", `${label}[${i}] is empty`);
		if (length(e) > ENTRY_MAX)
			return fail("INVALID_LIST", `${label}[${i}] is longer than ${ENTRY_MAX} characters`);
		if (match(e, CONTROL_RE) || index(e, chr(0)) >= 0)
			return fail("INVALID_LIST", `${label}[${i}] contains a control character`);
	}
	return null;
}

// The luci_sso_* login entries in config order, with their absolute section
// positions.
function sso_entries(uci) {
	let out = [];
	uci.foreach(CONFIG, null, (s) => {
		let name = substr(s[".name"], length(SECTION_PREFIX));
		if (s[".type"] != "login" || substr(s[".name"], 0, length(SECTION_PREFIX)) != SECTION_PREFIX)
			return;
		if (!length(name) || !match(name, NAME_RE))
			return;
		push(out, {
			section: s[".name"],
			index: s[".index"],
			role: { name, read: to_list(s.read), write: to_list(s.write) }
		});
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

function commit(uci) {
	if (!uci.commit(CONFIG))
		return fail("COMMIT_FAILED", `could not write /etc/config/${CONFIG}`);
	schedule_reload();
	return null;
}

// Moves `section` to absolute position `pos` and the section now at `pos` to
// where `section` was, leaving every other section where it is. uci's reorder
// shifts the sections in between, so the second move shifts them back.
function swap(uci, section, from, other, pos) {
	uci.reorder(CONFIG, section, pos);
	uci.reorder(CONFIG, other, from);
}

const methods = {
	list_roles: {
		call: function() {
			let uci = open_cursor();
			return { roles: map(sso_entries(uci), (e) => e.role), reload_pending: reload_timer != null };
		}
	},

	set_role: {
		args: { name: "name", read: [], write: [] },
		call: function(req) {
			let a = req.args;
			let err = check_name(a.name) || check_list("read", a.read) || check_list("write", a.write);
			if (err) return err;

			let uci = open_cursor();
			let section = SECTION_PREFIX + a.name;

			// A section of another type under an owned name is replaced.
			if (uci.get(CONFIG, section) != "login")
				uci.set(CONFIG, section, "login");

			uci.set(CONFIG, section, "username", USERNAME_PREFIX + a.name);
			uci.delete(CONFIG, section, "password");
			for (let opt in [ "read", "write" ]) {
				uci.delete(CONFIG, section, opt);
				if (length(a[opt]))
					uci.set(CONFIG, section, opt, a[opt]);
			}

			err = commit(uci);
			if (err) return err;
			return { role: { name: a.name, read: a.read, write: a.write } };
		}
	},

	delete_role: {
		args: { name: "name" },
		call: function(req) {
			let err = check_name(req.args.name);
			if (err) return err;

			let uci = open_cursor();
			let section = SECTION_PREFIX + req.args.name;
			if (uci.get(CONFIG, section) == null)
				return fail("NOT_FOUND", `no rpcd login entry for role '${req.args.name}'`);

			uci.delete(CONFIG, section);
			err = commit(uci);
			if (err) return err;
			return { result: true };
		}
	},

	move_role: {
		args: { name: "name", index: 0 },
		call: function(req) {
			let a = req.args;
			let err = check_name(a.name);
			if (err) return err;

			let uci = open_cursor();
			let entries = sso_entries(uci);
			let names = map(entries, (e) => e.role.name);
			let from = index(names, a.name);
			if (from < 0)
				return fail("NOT_FOUND", `no rpcd login entry for role '${a.name}'`);
			if (type(a.index) != "int" || a.index < 0 || a.index >= length(names))
				return fail("INVALID_INDEX", `index must be between 0 and ${length(names) - 1}`);

			// The target order, placed into the slots the entries occupy now.
			let order = filter(names, (n) => n != a.name);
			splice(order, a.index, 0, a.name);
			let slots = map(entries, (e) => e.index);

			for (let i = 0; i < length(order); i++) {
				let now = sso_entries(uci);
				let at = {};
				for (let e in now) at[e.role.name] = e;
				let want = at[order[i]];
				if (want.index == slots[i])
					continue;
				let occupant = filter(now, (e) => e.index == slots[i])[0];
				swap(uci, want.section, want.index, occupant.section, slots[i]);
			}

			err = commit(uci);
			if (err) return err;
			return { roles: map(sso_entries(uci), (e) => e.role) };
		}
	}
};

return { "luci-sso": methods };
