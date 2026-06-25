'use strict';
import { mock } from 'utest';
import * as Result from 'luci_sso.result';
import * as real_native from 'luci_sso.native';

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

	if (proxies.native)
		deps.native = proxies.native;

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
	let inject_state;
	if (name === 'fs') {
		// Seed ratelimit file as empty so router._check_rate_limit doesn't
		// die in strict mode when it reads an uninitialized path.
		// Seed ACL dir with an empty placeholder so _grant_all_luci_acls
		// returns Result.ok(0) without trying to destroy the session.
		let data = {
			"/var/run/luci-sso/ratelimit.json": "",
			"/usr/share/rpcd/acl.d/luci-base.json": "",
			...(state.data || {})
		};
		inject_state = { ...state, strict: true, data };
	} else if (name === 'native') {
		if (state.behavior) {
			// Behavior override requested (e.g. CSPRNG failure): go through the proxy.
			inject_state = state;
		} else {
			// No override needed: inject the real C extension directly so tier tests
			// exercise real crypto without relying on the proxy's real fallthrough.
			proxies[name] = real_native;
			do_inject(cfg, rest, proxies, cb);
			return;
		}
	} else {
		inject_state = { ...state, strict: true };
	}
	mock.inject(name, inject_state, function(proxy) {
		proxies[name] = proxy;
		do_inject(cfg, rest, proxies, cb);
	});
}

export const with_context = function(cfg, cb) {
	// Always inject native so deps.native is populated. If the caller does not
	// specify native in cfg, default to {} (non-strict; falls through to the real
	// C extension via the proxy fallback). Explicit cfg entries take precedence.
	let effective_cfg = { native: {}, ...cfg };
	let names = keys(effective_cfg);
	do_inject(effective_cfg, names, {}, cb);
};
