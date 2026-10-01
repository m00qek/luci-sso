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
 * Trusted proxies: a request whose REMOTE_ADDR is in the trusted_proxy option
 * (is_trusted_proxy) skips both budgets (exempt). Behind a reverse proxy every
 * request has the proxy's address, and uhttpd does not pass X-Forwarded-For
 * to CGI scripts, so luci-sso cannot tell the clients apart: the proxy must
 * limit them. The exemption covers these per-client budgets only. Every
 * global limit, such as the cap on pending handshakes, still applies.
 *
 * Concurrency: each writer renames its own uniquely named temporary file into
 * place. Two CGIs racing may lose an increment, but can never corrupt the
 * file. A corrupt file is treated as empty.
 *
 * @module luci_sso_ratelimit
 */

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as netaddr from 'luci_sso.netaddr';

export const STATE_FILE = "/var/run/luci-sso/ratelimit.json";

const LIMIT_LOGIN_REQUESTS  = 10;  // login initiations per client ...
const LIMIT_LOGIN_WINDOW    = 300; // ... per 5 minutes
const LIMIT_CLIENT_REQUESTS = 30;  // rate-limited requests per client ...
const LIMIT_CLIENT_WINDOW   = 60;  // ... per minute
const LIMIT_TRACKED_CLIENTS = 256; // most clients the state file remembers

// Seconds between two notices that a trusted proxy's request was exempted.
const EXEMPT_NOTICE_INTERVAL = 3600;

export const LIMITS = {
	login:   { requests: LIMIT_LOGIN_REQUESTS,  window: LIMIT_LOGIN_WINDOW },
	client:  { requests: LIMIT_CLIENT_REQUESTS, window: LIMIT_CLIENT_WINDOW },
	tracked: LIMIT_TRACKED_CLIENTS,
	notice:  EXEMPT_NOTICE_INTERVAL
};

/** Key shared by every client whose address cannot be parsed. */
export const UNKNOWN_CLIENT = "unknown";

/**
 * State-file key of the time the last exemption notice was logged (see
 * exempt). Every other key is a 16-hex client id, so it cannot collide.
 * @private
 */
const NOTICE_KEY = "notice";

// fe80::1%eth0: REMOTE_ADDR may carry a zone, which names an interface, not
// a host. Drop it.
function _strip_zone(addr) {
	let zone = index(addr, "%");
	return (zone >= 0) ? substr(addr, 0, zone) : addr;
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
	if (type(addr) != "string" || length(addr) > 64) return UNKNOWN_CLIENT;
	let a = netaddr.parse(_strip_zone(addr));
	if (!a) return UNKNOWN_CLIENT;
	if (a.family == 4) return "v4:" + netaddr.format(a);
	return sprintf("v6:%x:%x:%x:%x", a.parts[0], a.parts[1], a.parts[2], a.parts[3]);
};

/**
 * Whether a request's REMOTE_ADDR is a trusted reverse proxy, which skips
 * the per-client budgets (see exempt). Only REMOTE_ADDR counts: no request
 * header is read. An IPv4-mapped IPv6 address is its IPv4 address. An
 * address with a zone (fe80::1%eth0) is never trusted: the same link-local
 * address can be a different host on each interface, and an entry cannot
 * name the interface. Entries of `trusted` that are not an address or a CIDR
 * range are skipped (config.load refuses them anyway).
 *
 * @param {*} addr REMOTE_ADDR from the CGI environment.
 * @param {?array} trusted The trusted_proxy list: addresses and CIDR ranges.
 * @returns {boolean}
 */
export function is_trusted_proxy(addr, trusted) {
	if (type(trusted) != "array" || !length(trusted)) return false;
	if (type(addr) != "string" || length(addr) > 64) return false;
	let a = netaddr.parse(addr);
	if (!a) return false;
	for (let t in trusted) {
		if (netaddr.contains(netaddr.parse_cidr(t), a)) return true;
	}
	return false;
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

// Takes the last notice time out of `state` and returns it, or null when
// there is none, it is not a time, or EXEMPT_NOTICE_INTERVAL has passed since
// (or the clock went back).
function _notice_time(state, now) {
	let t = state[NOTICE_KEY];
	delete state[NOTICE_KEY];
	if (type(t) != "int" || now < t || now - t >= EXEMPT_NOTICE_INTERVAL) return null;
	return t;
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

	// The notice time is not a client: keep it out of the pruning and the cap.
	let notice_at = _notice_time(state, now);

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

	if (notice_at != null) state[NOTICE_KEY] = notice_at;
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

/**
 * Serves a request from a trusted proxy (is_trusted_proxy) without counting
 * it: it spends neither budget and takes no slot in the state file.
 *
 * So that the exemption is visible in the log, without a line per request,
 * the first exempted request logs a notice at `info`, and then at most one
 * every EXEMPT_NOTICE_INTERVAL seconds, whichever proxy it is for. The time
 * of the last notice is kept in the state file, which is written only when a
 * notice is logged.
 *
 * @param {*} deps `fs`, `clock`, `native`, `log`.
 * @param {string} key The proxy's client key, from client_key(), for the log.
 * @returns {{allowed: boolean, retry_after: int, budget: string}}
 */
export function exempt(deps, key) {
	let now = deps.clock.time();
	let state = _load(deps);
	if (_notice_time(state, now) == null) {
		let id_res = crypto.hash_sha256_hex(deps.native, key);
		let id = id_res.ok ? substr(id_res.data, 0, 16) : "unhashable";
		deps.log("info", `Request from trusted proxy [id: ${id}] skips the per-client rate limits (trusted_proxy); not logged again for ${EXEMPT_NOTICE_INTERVAL}s`);
		state[NOTICE_KEY] = now;
		_save(deps, state);
	}
	return { allowed: true, budget: null, retry_after: 0 };
};
