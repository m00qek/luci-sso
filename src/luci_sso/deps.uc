'use strict';

/**
 * Production dependency factory for luci-sso.
 *
 * Wires all real system modules (fs, ubus, uci, native crypto, HTTP client,
 * clock) into the single `deps` object consumed by every handler. Tests
 * replace individual entries via utest proxies instead of calling this.
 *
 * @module luci_sso_deps
 * @typedef {{
 *   fs:     module:fs,
 *   native: module:luci_sso.native,
 *   http:   HttpClient,
 *   ubus:   {call: (obj: string, method: string, args: *) => Result},
 *   uci:    *,
 *   clock:  Clock,
 *   log:    (level: string, msg: string) => void
 * }} Deps
 */

import * as fs          from 'fs';
import * as uci         from 'uci';
import * as ubus_mod    from 'ubus';
import * as log         from 'log';
import * as uloop       from 'uloop';
import * as uclient     from 'uclient';
import * as native      from 'luci_sso.native';
import * as http_client from 'luci_sso.components.http_client';
import * as clock_mod   from 'luci_sso.components.clock';
import * as Result      from 'luci_sso.result';

/**
 * Constructs the production `Deps` object.
 *
 * Opens a syslog channel, connects to ubus, and instantiates the HTTP client
 * and clock components. Called once at handler startup; never called in tests.
 *
 * @returns {Deps}
 */
/**
 * Wraps a raw ubus connection into the `deps.ubus` channel: a single `call`
 * method that normalises the outcome into a Result.
 *
 * @param {*} conn - The object returned by `ubus.connect()` (may be null).
 * @returns {{call: (obj: string, method: string, args: *) => Result}}
 */
export function ubus_channel(conn) {
	return {
		call: (obj, method, args) => {
			if (!conn) return Result.err("UBUS_CONNECT_FAILED");
			let res = conn.call(obj, method, args);
			if (res === null) return Result.err("UBUS_ERROR");
			return Result.ok(res);
		}
	};
};

/**
 * Opens a syslog channel and returns the `deps.log` function, mapping the
 * caller's level string to the corresponding syslog priority.
 *
 * @param {module:log} log_mod - The `log` module (or a compatible stand-in).
 * @returns {(level: string, msg: string) => void}
 */
export function syslog_channel(log_mod) {
	log_mod.openlog("luci-sso", log_mod.LOG_PID, log_mod.LOG_USER);
	return function(level, msg) {
		let priority = (level == "error")   ? log_mod.LOG_ERR     :
		               (level == "warn")    ? log_mod.LOG_WARNING  :
		               (level == "debug")   ? log_mod.LOG_DEBUG    : log_mod.LOG_INFO;
		log_mod.syslog(priority, msg);
	};
};

export function create() {
	return {
		fs:     fs,
		native: native,
		http:   http_client.create(uclient, uloop, fs),
		ubus:   ubus_channel(ubus_mod.connect()),
		uci:    uci.cursor(),
		clock:  clock_mod.create(uloop),
		log:    syslog_channel(log)
	};
};
