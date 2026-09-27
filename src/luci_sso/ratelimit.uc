"use strict";

/**
 * Per-client rate limiting for the CGI endpoints.
 *
 * Each client gets two fixed-window budgets:
 *   - login initiation (GET / without ?action=enabled): LIMIT_LOGIN_REQUESTS
 *     per LIMIT_LOGIN_WINDOW seconds. Every initiation writes a handshake, so
 *     this also caps how many handshakes one client can hold at once.
 *   - every rate-limited request: LIMIT_CLIENT_REQUESTS per
 *     LIMIT_CLIENT_WINDOW seconds, a CPU guard. The callback and logout count
 *     only toward this one.
 * There is deliberately no global budget: one busy client must not lock
 * everyone else out. uhttpd's cap on concurrent CGI processes is the
 * router-wide backstop.
 *
 * A client is its REMOTE_ADDR: the full address for IPv4, the /64 prefix for
 * IPv6 (one host usually owns a whole /64). Counters live in ONE small JSON
 * file keyed by a truncated SHA-256 of the client key, so no address is
 * stored. At most LIMIT_TRACKED_CLIENTS entries are kept.
 *
 * Concurrency: each writer renames its own uniquely named temporary file into
 * place. Two CGIs racing may lose an increment, but can never corrupt the
 * file. A corrupt file is treated as empty.
 *
 * @module luci_sso_ratelimit
 */

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';

export const STATE_FILE = "/var/run/luci-sso/ratelimit.json";

const LIMIT_LOGIN_REQUESTS  = 10;  // login initiations per client ...
const LIMIT_LOGIN_WINDOW    = 300; // ... per 5 minutes
const LIMIT_CLIENT_REQUESTS = 30;  // rate-limited requests per client ...
const LIMIT_CLIENT_WINDOW   = 60;  // ... per minute
const LIMIT_TRACKED_CLIENTS = 256; // most clients the state file remembers

export const LIMITS = {
	login:   { requests: LIMIT_LOGIN_REQUESTS,  window: LIMIT_LOGIN_WINDOW },
	client:  { requests: LIMIT_CLIENT_REQUESTS, window: LIMIT_CLIENT_WINDOW },
	tracked: LIMIT_TRACKED_CLIENTS
};

/** Key shared by every client whose address cannot be parsed. */
export const UNKNOWN_CLIENT = "unknown";

function _ipv4(s) {
	let m = match(s, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m) return null;
	let out = [];
	for (let i = 1; i <= 4; i++) {
		let n = int(m[i]);
		if (n > 255) return null;
		push(out, n);
	}
	return out;
}

// Expands an IPv6 address to 8 integers, or null. Accepts :: compression and
// an embedded IPv4 tail (::ffff:192.0.2.1).
function _ipv6(s) {
	let tail4 = null;
	let m = match(s, /^(.*:)([0-9]{1,3}(\.[0-9]{1,3}){3})$/);
	if (m) {
		tail4 = _ipv4(m[2]);
		if (!tail4) return null;
		s = m[1] + "0:0";                  // placeholder for the two IPv4 groups
	}

	let halves = split(s, "::");
	if (length(halves) > 2) return null;

	let parse = (part) => {
		if (part == "") return [];
		let groups = [];
		for (let g in split(part, ":")) {
			if (!match(g, /^[0-9A-Fa-f]{1,4}$/)) return null;
			push(groups, hex(g));
		}
		return groups;
	};

	let head = parse(halves[0]);
	let rest = (length(halves) == 2) ? parse(halves[1]) : [];
	if (head == null || rest == null) return null;

	let groups;
	if (length(halves) == 2) {
		let fill = 8 - length(head) - length(rest);
		if (fill < 1) return null;
		groups = [ ...head ];
		for (let i = 0; i < fill; i++) push(groups, 0);
		for (let g in rest) push(groups, g);
	} else {
		groups = head;
	}
	if (length(groups) != 8) return null;

	if (tail4) {
		groups[6] = tail4[0] * 256 + tail4[1];
		groups[7] = tail4[2] * 256 + tail4[3];
	}
	return groups;
}

/**
 * Maps a REMOTE_ADDR value to a rate-limit client key.
 *
 *   IPv4                   "v4:<a.b.c.d>"      (full address)
 *   IPv4-mapped IPv6       "v4:<a.b.c.d>"      (the embedded IPv4)
 *   IPv6                   "v6:<g1:g2:g3:g4>"  (the /64, canonical lowercase)
 *   empty or unparseable   UNKNOWN_CLIENT      (one shared bucket)
 *
 * @param {*} addr REMOTE_ADDR from the CGI environment.
 * @returns {string}
 */
export function client_key(addr) {
	if (type(addr) != "string" || length(addr) == 0 || length(addr) > 64)
		return UNKNOWN_CLIENT;

	let v4 = _ipv4(addr);
	if (v4) return "v4:" + join(".", v4);

	let s = addr;
	let zone = index(s, "%");              // fe80::1%eth0: drop the zone
	if (zone >= 0) s = substr(s, 0, zone);
	if (index(s, ":") < 0) return UNKNOWN_CLIENT;

	let g = _ipv6(s);
	if (!g) return UNKNOWN_CLIENT;

	// ::ffff:a.b.c.d is an IPv4 client reaching a dual-stack socket.
	if (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff)
		return sprintf("v4:%d.%d.%d.%d", g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255);

	return sprintf("v6:%x:%x:%x:%x", g[0], g[1], g[2], g[3]);
};

// Advances a [window_start, count] pair: a new window once the old one ends.
function _bump(w, now, window) {
	if (type(w) != "array" || length(w) != 2 || type(w[0]) != "int" || type(w[1]) != "int" || now - w[0] >= window)
		return [ now, 1 ];
	return [ w[0], w[1] + 1 ];
}

function _live(w, now, window) {
	return type(w) == "array" && length(w) == 2 && type(w[0]) == "int" && now - w[0] < window;
}

function _load(deps) {
	let raw = null;
	try { raw = deps.fs.readfile(STATE_FILE); } catch (e) { raw = null; }
	if (!raw) return {};

	let res = encoding.safe_json(raw);
	if (!res.ok || type(res.data) != "object") {
		deps.log("warn", "Rate limit state file is corrupt; starting from empty");
		return {};
	}
	return res.data;
}

function _save(deps, state) {
	let rnd = crypto.random(deps.native, 8);
	if (!rnd.ok) {
		deps.log("error", "Rate limit state not saved: CSPRNG failure");
		return;
	}
	let tmp = `${STATE_FILE}.${encoding.b64url_encode(rnd.data).data}.tmp`;
	try {
		if (!deps.fs.writefile(tmp, sprintf("%J", state))) {
			deps.log("error", "Failed to write rate limit state file");
			return;
		}
		if (!deps.fs.rename(tmp, STATE_FILE)) {
			deps.log("error", "Failed to install rate limit state file");
			deps.fs.unlink(tmp);
		}
	} catch (e) {
		deps.log("error", `Rate limit state write failed: ${e}`);
	}
}

/**
 * Counts one request from `key` and decides whether to serve it.
 *
 * @param {*} deps `fs`, `clock`, `native`, `log`.
 * @param {string} key A client key from client_key().
 * @param {boolean} is_login True for a login initiation (GET / without ?action).
 * @returns {{allowed: boolean, retry_after: int, budget: string}}
 */
export function check(deps, key, is_login) {
	let now = deps.clock.time();
	let id_res = crypto.hash_sha256_hex(deps.native, key);
	let id = id_res.ok ? substr(id_res.data, 0, 16) : "unhashable";

	let state = _load(deps);

	// Prune: drop windows that have ended, and entries with nothing left.
	for (let k in keys(state)) {
		let e = state[k];
		if (type(e) != "object") { delete state[k]; continue; }
		if (!_live(e.g, now, LIMIT_CLIENT_WINDOW)) delete e.g;
		if (!_live(e.l, now, LIMIT_LOGIN_WINDOW)) delete e.l;
		if (!e.g && !e.l) delete state[k];
	}

	let e = state[id] || {};
	e.g = _bump(e.g, now, LIMIT_CLIENT_WINDOW);
	if (is_login) e.l = _bump(e.l, now, LIMIT_LOGIN_WINDOW);
	e.seen = now;
	state[id] = e;

	// Keep the LIMIT_TRACKED_CLIENTS most recently seen clients.
	let ids = keys(state);
	if (length(ids) > LIMIT_TRACKED_CLIENTS) {
		sort(ids, (a, b) => (state[a].seen || 0) - (state[b].seen || 0));
		for (let i = 0; i < length(ids) - LIMIT_TRACKED_CLIENTS; i++)
			delete state[ids[i]];
	}

	_save(deps, state);

	if (is_login && e.l[1] > LIMIT_LOGIN_REQUESTS) {
		deps.log("warn", `Login rate limit exceeded for client [id: ${id}]: ${e.l[1]} in ${LIMIT_LOGIN_WINDOW}s [limit: ${LIMIT_LOGIN_REQUESTS}]`);
		return { allowed: false, budget: "login", retry_after: e.l[0] + LIMIT_LOGIN_WINDOW - now };
	}
	if (e.g[1] > LIMIT_CLIENT_REQUESTS) {
		deps.log("warn", `Request rate limit exceeded for client [id: ${id}]: ${e.g[1]} in ${LIMIT_CLIENT_WINDOW}s [limit: ${LIMIT_CLIENT_REQUESTS}]`);
		return { allowed: false, budget: "client", retry_after: e.g[0] + LIMIT_CLIENT_WINDOW - now };
	}
	return { allowed: true, budget: null, retry_after: 0 };
};
