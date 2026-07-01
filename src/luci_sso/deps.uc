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
export function create() {
	log.openlog("luci-sso", log.LOG_PID, log.LOG_USER);

	const syslog = function(level, msg) {
		let priority = (level == "error")   ? log.LOG_ERR     :
		               (level == "warn")    ? log.LOG_WARNING  :
		               (level == "debug")   ? log.LOG_DEBUG    : log.LOG_INFO;
		log.syslog(priority, msg);
	};

	let _conn = ubus_mod.connect();

	return {
		fs:     fs,
		native: native,
		http:  http_client.create(uclient, uloop, fs),
		ubus:  {
			call: (obj, method, args) => {
				if (!_conn) return Result.err("UBUS_CONNECT_FAILED");
				let res = _conn.call(obj, method, args);
				if (res === null) return Result.err("UBUS_ERROR");
				return Result.ok(res);
			}
		},
		uci:   uci.cursor(),
		clock: clock_mod.create(uloop),
		log:   syslog
	};
};
