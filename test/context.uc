'use strict';
import { mock } from 'utest';
import * as Result from 'luci_sso.result';
import * as real_native from 'luci_sso.native';
import { ubus_channel } from 'luci_sso.deps';

/**
 * Reply value for a mocked ubus method that succeeds without data, the way
 * rpcd answers `session set`, `grant` and `destroy`. The real ucode binding
 * returns null for such a reply with error() unset; a mocked null cannot say
 * that, because the utest proxy has no error(), so this marker stands in for it.
 */
export const UBUS_NO_DATA = { "__utest_ubus_no_data": true };

/**
 * Builds deps.ubus from a utest ubus connection through the PRODUCTION
 * channel (luci_sso.deps.ubus_channel), so tests exercise the same
 * null-reply handling as the router.
 *
 * The utest connection has no error(), so this adapter supplies one:
 *   - a mocked null reply is a failed call: call() returns null and error()
 *     reports it, as rpcd does for e.g. an unknown session;
 *   - UBUS_NO_DATA is a successful call with no data: null with no error;
 *   - any other reply is returned as-is.
 */
export function mock_ubus_channel(conn) {
	if (!conn) return ubus_channel(null);
	let last_error = null;
	let channel = ubus_channel({
		call: (obj, method, args) => {
			let raw = conn.call(obj, method, args);
			last_error = (raw === null) ? `mock: ${obj}.${method} failed` : null;
			if (type(raw) == "object" && raw.__utest_ubus_no_data) return null;
			return raw;
		},
		error: () => last_error
	});
	// Keep the connection's spy handle reachable as spy(deps.ubus).
	channel.__utest__ = conn.__utest__;
	return channel;
};

function build_deps(proxies) {
	let deps = {};

	if (proxies.fs)
		deps.fs = proxies.fs;

	if (proxies.uci)
		deps.uci = proxies.uci.cursor();

	if (proxies.ubus)
		deps.ubus = mock_ubus_channel(proxies.ubus.connect());

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
	} else if (name === 'uci') {
		// Every OpenWrt router ships /etc/config/luci; ubus.create_passwordless_session
		// reads luci.sauth.sessiontime from it. Seed the stock value so strict uci
		// mocks don't die on a package the test never meant to exercise.
		let data = { luci: { sauth: { ".type": "internal", sessiontime: "3600" } }, ...(state.data || {}) };
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
