"use strict";

/**
 * The rpcd login entries that hold the permissions of luci-sso's roles, and
 * rpcd's rules for them.
 *
 * Each role `<role>` has exactly one entry in /etc/config/rpcd, written by the
 * `luci-sso` ubus object (files/usr/share/rpcd/ucode/luci-sso.uc):
 *
 *   config login 'luci_sso_<role>'
 *   	option username 'sso:<role>'
 *   	list read '<access group or pattern>'
 *   	list write '<access group or pattern>'
 *
 * and never a password option: rpcd's password login skips an entry without
 * one, so the entry can rebuild SSO sessions on an rpcd reload but can never
 * be used to log in.
 */

export const CONFIG = "rpcd";
export const SECTION_PREFIX = "luci_sso_";
export const USERNAME_PREFIX = "sso:";

/** The section name of a role's entry. */
export function section_name(role) {
	return SECTION_PREFIX + role;
};

/** The username of a role's entry, which its SSO sessions carry. */
export function username(role) {
	return USERNAME_PREFIX + role;
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
