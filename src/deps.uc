'use strict';

import * as fs          from 'fs';
import * as uci         from 'uci';
import * as ubus_mod    from 'ubus';
import * as log         from 'log';
import * as uloop       from 'uloop';
import * as uclient     from 'uclient';
import * as http_client from 'luci_sso.components.http_client';
import * as clock_mod   from 'luci_sso.components.clock';
import * as Result      from 'luci_sso.result';

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
		fs:    fs,
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
