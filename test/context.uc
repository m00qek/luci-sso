'use strict';
import { mock } from 'utest';
import * as Result from 'luci_sso.result';

function build_deps(proxies) {
	let deps = {};

	if (proxies.fs)
		deps.fs = proxies.fs;

	if (proxies.uci)
		deps.uci = proxies.uci.cursor();

	if (proxies.ubus) {
		let conn = proxies.ubus.connect();
		deps.ubus = {
			__utest__: conn ? conn.__utest__ : null,
			call: function(obj, method, args) {
				let res = conn.call(obj, method, args);
				if (res === null) return Result.err("UBUS_ERROR");
				return Result.ok(res);
			}
		};
	}

	if (proxies.http_client)
		deps.http = proxies.http_client.create(null, null, null);

	if (proxies.clock)
		deps.clock = proxies.clock.create(null, null);

	deps.log = function(level, msg) {};

	return deps;
}

function do_inject(cfg, remaining, proxies, cb) {
	if (length(remaining) == 0) {
		cb(build_deps(proxies));
		return;
	}
	let name = remaining[0];
	let rest = slice(remaining, 1);
	let state = cfg[name] || {};
	mock.inject(name, { ...state, strict: true }, function(proxy) {
		proxies[name] = proxy;
		do_inject(cfg, rest, proxies, cb);
	});
}

export const with_context = function(cfg, cb) {
	let names = keys(cfg);
	do_inject(cfg, names, {}, cb);
};
