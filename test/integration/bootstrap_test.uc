import { describe, it, assert, contains } from 'utest';
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

	it('returns UBUS_ERROR when the underlying call returns null', () => {
		let ch = ubus_channel({ call: () => null });
		assert.match(contains({ ok: false, error: 'UBUS_ERROR' }), ch.call('session', 'create', {}));
	});

	it('returns Result.ok wrapping the raw ubus response on success', () => {
		let ch = ubus_channel({ call: () => ({ ubus_rpc_session: 'sid' }) });
		assert.match(contains({ ok: true, data: { ubus_rpc_session: 'sid' } }), ch.call('session', 'create', {}));
	});

	it('forwards (obj, method, args) to the underlying connection verbatim', () => {
		let seen = null;
		let ch = ubus_channel({ call: (obj, method, args) => { seen = [obj, method, args]; return {}; } });
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

// Builds a fake `log` module that records openlog/syslog calls.
function fake_log() {
	let opens = [];
	let lines = [];
	return {
		...LOG,
		openlog: (ident, opt, fac) => push(opens, [ident, opt, fac]),
		syslog:  (priority, msg) => push(lines, [priority, msg]),
		opens:   () => opens,
		lines:   () => lines,
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
