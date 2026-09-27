"use strict";

/**
 * The rpcd login entries that hold the permissions of luci-sso's roles, and
 * rpcd's rules for them: one place for every rule that the login path
 * (ubus.uc), the `luci-sso` ubus object (files/usr/share/rpcd/ucode/luci-sso.uc)
 * and the upgrade script (files/etc/uci-defaults/20-luci-sso-rpcd) share.
 *
 * Each role `<role>` has exactly one entry in /etc/config/rpcd:
 *
 *   config login 'luci_sso_<role>'
 *   	option username 'sso:<role>'
 *   	list read '<access group or pattern>'
 *   	list write '<access group or pattern>'
 *
 * and never a password option: rpcd's password login skips an entry without
 * one, so the entry can rebuild SSO sessions on an rpcd reload but can never
 * be used to log in.
 *
 * The read list always grants the `unauthenticated` access group. LuCI calls
 * session.access and luci.getFeatures, which that group grants, on every
 * page, and treats a session that may call neither as expired. A read list
 * that already grants the group, through the name itself or a pattern such as
 * `*`, is kept as it is; any other gets the name appended. A read list with a
 * negation that denies the group is refused, since no addition could undo it.
 */

import * as Result from 'luci_sso.result';

export const CONFIG = "rpcd";
export const SECTION_PREFIX = "luci_sso_";
export const USERNAME_PREFIX = "sso:";

/** The access group every role's read list grants (see above). */
export const BASELINE_GROUP = "unauthenticated";

// Role names become part of a UCI section name, so they use its alphabet.
export const NAME_MAX = 32;
const NAME_RE = /^[A-Za-z0-9_]+$/;

// Access group names and rpcd patterns (globs, "!" negations) are short.
export const LIST_MAX = 128;
export const ENTRY_MAX = 128;
// NUL cannot appear in a POSIX regex, so it is checked on its own.
const CONTROL_RE = regexp("[\x01-\x1f\x7f]");

/** The section name of a role's entry. */
export function section_name(role) {
	return SECTION_PREFIX + role;
};

/** The username of a role's entry, which its SSO sessions carry. */
export function username(role) {
	return USERNAME_PREFIX + role;
};

/**
 * Checks a role name: 1 to NAME_MAX letters, digits and underscores.
 * @returns {object} - Result: ok(name), or err("INVALID_NAME", message)
 */
export function check_name(name) {
	if (type(name) != "string" || !length(name))
		return Result.err("INVALID_NAME", "name is required");
	if (length(name) > NAME_MAX)
		return Result.err("INVALID_NAME", `name is longer than ${NAME_MAX} characters`);
	if (!match(name, NAME_RE))
		return Result.err("INVALID_NAME", "name may contain only letters, digits and underscores");
	return Result.ok(name);
};

/**
 * Checks a read or write list: an array of at most LIST_MAX non-empty
 * strings of at most ENTRY_MAX characters, without control characters.
 * @param {string} label - "read" or "write", for the message
 * @returns {object} - Result: ok(list), or err("INVALID_LIST", message)
 */
export function check_list(label, list) {
	if (type(list) != "array")
		return Result.err("INVALID_LIST", `${label} must be an array of strings`);
	if (length(list) > LIST_MAX)
		return Result.err("INVALID_LIST", `${label} has more than ${LIST_MAX} entries`);
	for (let i = 0; i < length(list); i++) {
		let e = list[i];
		if (type(e) != "string")
			return Result.err("INVALID_LIST", `${label}[${i}] is not a string`);
		if (!length(e))
			return Result.err("INVALID_LIST", `${label}[${i}] is empty`);
		if (length(e) > ENTRY_MAX)
			return Result.err("INVALID_LIST", `${label}[${i}] is longer than ${ENTRY_MAX} characters`);
		if (match(e, CONTROL_RE) || index(e, chr(0)) >= 0)
			return Result.err("INVALID_LIST", `${label}[${i}] contains a control character`);
	}
	return Result.ok(list);
};

// fnmatch(3) without flags, as rpcd matches role lists against group names:
// `*` and `?` are wildcards and `[...]` is a character class ([!...] negates).
function glob_regexp(pattern) {
	let out = "^";
	for (let i = 0; i < length(pattern); i++) {
		let ch = substr(pattern, i, 1);
		if (ch == "*") out += ".*";
		else if (ch == "?") out += ".";
		else if (ch == "[") {
			let j = index(substr(pattern, i + 1), "]");
			if (j < 1) { out += "\\["; continue; }
			let body = substr(pattern, i + 1, j);
			if (substr(body, 0, 1) == "!") body = "^" + substr(body, 1);
			out += "[" + replace(body, /\\/g, "\\\\") + "]";
			i += j + 1;
		}
		else out += (index("\\.^$|+(){}]", ch) >= 0) ? "\\" + ch : ch;
	}
	return regexp(out + "$");
}

function glob_matches(pattern, group) {
	return match(group, glob_regexp(pattern)) != null;
}

// The pattern of a negation ("!pattern"), or null for a positive entry.
// rpcd skips whitespace after the "!" only, and ignores an empty negation.
function negated(entry) {
	if (substr(entry, 0, 1) != "!") return null;
	let p = ltrim(substr(entry, 1));
	return length(p) ? p : null;
}

// One list against a group, as rpcd's rpc_login_test_permission reads it:
// true (allowed), false (denied by a negation) or null (no entry matches).
// Negations are checked first.
function list_verdict(list, group) {
	if (type(list) != "array") return null;
	for (let p in list) {
		if (type(p) != "string") continue;
		let neg = negated(p);
		if (neg != null && glob_matches(neg, group)) return false;
	}
	for (let p in list) {
		if (type(p) != "string" || !length(p) || substr(p, 0, 1) == "!") continue;
		if (glob_matches(p, group)) return true;
	}
	return null;
}

/**
 * Whether an entry with these lists has `perm` ("read" or "write") on an
 * access group, exactly as rpcd decides it: fnmatch(3) patterns, so `*`
 * matches every group; a negation in the permission's own list denies before
 * any positive entry allows; and a read that the read list neither allows nor
 * denies falls back to the write list (write implies read). rpcd only reads
 * list options: a single `option read` is ignored, so only arrays count here.
 *
 * @param {object} lists - { read, write }
 * @param {string} perm - "read" or "write"
 * @param {string} group - An access group name
 * @returns {boolean}
 */
export function permits(lists, perm, group) {
	let v = list_verdict(lists[perm], group);
	if (v != null) return v;
	return (perm == "read") ? (list_verdict(lists.write, group) == true) : false;
};

/**
 * The read list a role's entry stores: the list as given, plus the
 * `unauthenticated` group appended when the list does not grant it already
 * (see the module comment). Applying it twice gives the same list.
 *
 * @param {array} read - A checked read list
 * @returns {object} - Result: ok(list), or err("INVALID_LIST", message) when a
 *   negation in the list denies the group
 */
export function with_baseline(read) {
	let v = list_verdict(read, BASELINE_GROUP);
	if (v == false)
		return Result.err("INVALID_LIST", `read must not deny '${BASELINE_GROUP}': LuCI needs it to check the session`);
	if (v == true) return Result.ok(read);
	return Result.ok([ ...read, BASELINE_GROUP ]);
};

/**
 * Checks a role name and its lists and returns the entry to store for it.
 *
 * @returns {object} - Result: ok({ name, section, username, read, write }),
 *   with the read list as with_baseline() returns it, or err(code, message)
 *   with code INVALID_NAME or INVALID_LIST
 */
export function entry(name, read, write) {
	let res = check_name(name);
	if (!res.ok) return res;
	res = check_list("read", read);
	if (!res.ok) return res;
	res = check_list("write", write);
	if (!res.ok) return res;
	res = with_baseline(read);
	if (!res.ok) return res;
	return Result.ok({ name, section: section_name(name), username: username(name), read: res.data, write });
};

/**
 * Stages an entry, as entry() returns it, on a UCI cursor: the section
 * becomes a login (a section of another type under the name is replaced), its
 * username is set, a password option is removed, and each list is replaced,
 * or removed when empty. Touches no other section. The caller commits.
 *
 * @param {object} uci - A UCI cursor, which the caller opened and commits
 * @param {object} e - An entry from entry()
 */
export function stage(uci, e) {
	if (uci.get(CONFIG, e.section) != "login")
		uci.set(CONFIG, e.section, "login");
	uci.set(CONFIG, e.section, "username", e.username);
	uci.delete(CONFIG, e.section, "password");
	for (let opt in [ "read", "write" ]) {
		uci.delete(CONFIG, e.section, opt);
		if (length(e[opt]))
			uci.set(CONFIG, e.section, opt, e[opt]);
	}
};

// A role's read/write option as a list. Before role permissions moved to rpcd,
// luci-sso read a single option as a one-entry list, so the upgrade does too.
function old_list(v) {
	if (type(v) == "array") return v;
	return (v != null) ? [ v ] : [];
}

/** The role the package ships, whose entry the upgrade creates if missing. */
export const DEFAULT_ROLE = "admin";

/**
 * Moves role permissions from /etc/config/luci-sso to rpcd login entries: the
 * upgrade from releases that kept read/write lists on the luci-sso role.
 *
 * For each luci-sso role that still has a read or write option, in config
 * order, the role's entry is created or replaced from those lists, by the same
 * rules as the luci-sso ubus object (entry() and stage(): the
 * `unauthenticated` group added, rpcd's meaning of every pattern, no
 * password), and the options are removed from the role. A role whose name or
 * lists the rules refuse keeps its options, and a warning names it: its users
 * cannot log in until its permissions are saved on the settings page.
 *
 * Then, if the role the package ships (`admin`) exists and has no entry, its
 * entry is created with read '*' and write '*', the permissions it ships
 * with. That covers a fresh install, where the shipped role has no lists.
 *
 * Touches no rpcd section but luci_sso_<role> ones, never the order of the
 * luci-sso roles, and nothing at all when there is nothing to do, so running
 * it again changes nothing. Stages the changes on the cursor; the caller
 * commits rpcd before luci-sso, so an interrupted upgrade that committed
 * only the first is completed by the next run.
 *
 * @param {object} uci - A UCI cursor
 * @param {function} warn - Called with a message for each role left alone
 * @returns {object} - { rpcd, luci_sso }: whether each configuration changed
 */
export function migrate(uci, warn) {
	let changed = { rpcd: false, luci_sso: false };

	let roles = [];
	uci.foreach("luci-sso", "role", (s) => {
		if (s.read != null || s.write != null) push(roles, s);
	});

	for (let s in roles) {
		let name = s[".name"];
		let res = entry(name, old_list(s.read), old_list(s.write));
		if (!res.ok) {
			warn(`role '${name}' keeps its read/write lists and has no rpcd login entry: ${res.details}; save its permissions on the settings page`);
			continue;
		}
		stage(uci, res.data);
		uci.delete("luci-sso", name, "read");
		uci.delete("luci-sso", name, "write");
		changed.rpcd = changed.luci_sso = true;
	}

	if (uci.get("luci-sso", DEFAULT_ROLE) == "role" && uci.get(CONFIG, section_name(DEFAULT_ROLE)) == null) {
		stage(uci, entry(DEFAULT_ROLE, [ "*" ], [ "*" ]).data);
		changed.rpcd = true;
	}

	return changed;
};
