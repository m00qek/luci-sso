import { describe, it, assert, contains } from 'utest';
import * as fs from 'fs';
import { ubus_channel, syslog_channel } from 'luci_sso.deps';

// Integration bucket — the composition root. deps.create() wires the real system
// modules (fs/uci/ubus/uclient/uloop/log) into the deps graph; that call itself
// depends on a live ubusd/syslog and so belongs to e2e. The two pieces of real
// wiring *logic* it contains — the ubus Result-adapter and the syslog level→
// priority mapping — are extracted as pure builders and asserted here. `conn`
// and the log module are ordinary arguments (not proxied modules), so plain
// capture fakes are the idiomatic driver.

// ─── ubus_channel ──────────────────────────────────────────────────────────────

describe('deps.ubus_channel', () => {
	it('returns UBUS_CONNECT_FAILED when there is no connection', () => {
		let ch = ubus_channel(null);
		assert.match(contains({ ok: false, error: 'UBUS_CONNECT_FAILED' }), ch.call('obj', 'method', {}));
	});

	it('returns UBUS_ERROR with the connection error when the call fails', () => {
		let ch = ubus_channel({ call: () => null, error: () => 'Not found' });
		assert.match(contains({ ok: false, error: 'UBUS_ERROR', details: 'Not found' }), ch.call('session', 'set', {}));
	});

	it('returns Result.ok(null) for a successful call that replies with no data', () => {
		// rpcd answers session set/grant/destroy with no data; ucode returns null
		// and error() stays null. Treating that as failure broke every grant/destroy.
		let ch = ubus_channel({ call: () => null, error: () => null });
		assert.match(contains({ ok: true, data: null }), ch.call('session', 'set', {}));
	});

	it('returns Result.ok wrapping the raw ubus response on success', () => {
		let ch = ubus_channel({ call: () => ({ ubus_rpc_session: 'sid' }), error: () => null });
		assert.match(contains({ ok: true, data: { ubus_rpc_session: 'sid' } }), ch.call('session', 'create', {}));
	});

	it('forwards (obj, method, args) to the underlying connection verbatim', () => {
		let seen = null;
		let ch = ubus_channel({ call: (obj, method, args) => { seen = [obj, method, args]; return {}; }, error: () => null });
		ch.call('session', 'grant', { scope: 'x' });
		assert.match('session',        seen[0]);
		assert.match('grant',          seen[1]);
		assert.match({ scope: 'x' },   seen[2]);
	});
});

// ─── syslog_channel ─────────────────────────────────────────────────────────────

// Sentinel priority values so the level→priority mapping is observable.
const LOG = {
	LOG_PID: 1, LOG_USER: 8,
	LOG_ERR: 3, LOG_WARNING: 4, LOG_DEBUG: 7, LOG_INFO: 6,
};

// Builds a fake `log` module that records openlog/syslog calls. Each line is
// [priority, the text syslog() would write]: like ucode's own log.syslog, the
// fake formats a string format with the real sprintf(), so a message passed
// as the format, not as its argument, shows here as it would in the log.
function fake_log() {
	let opens = [];
	let lines = [];
	let calls = [];
	return {
		...LOG,
		openlog: (ident, opt, fac) => push(opens, [ident, opt, fac]),
		syslog:  (priority, fmt, ...args) => {
			push(calls, [priority, fmt, ...args]);
			push(lines, [priority, sprintf(fmt, ...args)]);
		},
		opens:   () => opens,
		lines:   () => lines,
		calls:   () => calls,
	};
}

describe('deps.syslog_channel', () => {
	it('opens the syslog channel once with the luci-sso identity', () => {
		let log = fake_log();
		syslog_channel(log);
		assert.match(1, length(log.opens()));
		assert.match('luci-sso', log.opens()[0][0]);
		assert.match(LOG.LOG_PID,  log.opens()[0][1]);
		assert.match(LOG.LOG_USER, log.opens()[0][2]);
	});

	it('maps each level to its syslog priority and forwards the message', () => {
		let log = fake_log();
		let emit = syslog_channel(log);

		emit('error', 'e');
		emit('warn',  'w');
		emit('debug', 'd');
		emit('info',  'i');
		emit('trace', 't'); // unknown level → LOG_INFO

		assert.match([LOG.LOG_ERR,     'e'], log.lines()[0]);
		assert.match([LOG.LOG_WARNING, 'w'], log.lines()[1]);
		assert.match([LOG.LOG_DEBUG,   'd'], log.lines()[2]);
		assert.match([LOG.LOG_INFO,    'i'], log.lines()[3]);
		assert.match([LOG.LOG_INFO,    't'], log.lines()[4]);
	});
});

describe('deps.syslog_channel — format string', () => {
	it('passes the message as the argument of a constant "%s" format', () => {
		let log = fake_log();
		let emit = syslog_channel(log);
		emit('warn', 'IDP_ERROR: the IdP returned error=%n%s');
		assert.match([[LOG.LOG_WARNING, '%s', 'IDP_ERROR: the IdP returned error=%n%s']], log.calls());
	});

	it('logs printf conversions in request data literally, at their own length', () => {
		// The unauthenticated memory DoS: return_to or the callback's error
		// parameter holding width specifiers. As a format, each %9999999d
		// would expand to ten million characters.
		let log = fake_log();
		let emit = syslog_channel(log);
		let msg = 'Ignoring return_to "%9999999d%9999999d%s%J%%": not a LuCI page';
		emit('info', msg);
		assert.match([LOG.LOG_INFO, msg], log.lines()[0]);
		assert.match(length(msg), length(log.lines()[0][1]));
	});
});

// The real `log` module, in a child ucode process: LOG_PERROR makes syslog()
// copy each line to standard error, where this test reads it back.
const LOG_PERROR = 0x20;

describe('deps.syslog_channel — the real log module', () => {
	it('writes a message holding printf conversions to the log literally', () => {
		let script = join("\n", [
			'import * as log from "log";',
			'import { syslog_channel } from "luci_sso.deps";',
			`let real = { ...log, openlog: (ident, opt, fac) => log.openlog(ident, opt | ${LOG_PERROR}, fac) };`,
			'syslog_channel(real)("warn", "IDP_ERROR: error=%9999999d%9999999d%s%%");'
		]);
		let p = fs.popen(`ucode -e '${script}' 2>&1`, "r");
		let out = p.read("all");
		p.close();
		assert.match(true, index(out, "IDP_ERROR: error=%9999999d%9999999d%s%%") >= 0, out);
		assert.match(true, length(out) < 1000, `${length(out)} bytes written`);
	});
});
