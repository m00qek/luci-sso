import { describe, it, assert, contains, mock, spy } from 'utest';
import * as rl from 'luci_sso.ratelimit';
import * as native from 'luci_sso.native';

const NOW = 1700000000;

// Runs `fn(deps, set_now, fs)` with a strict fs holding `data` and a clock
// whose time the test controls. The state file lives in the mock store, so
// successive check() calls see each other's writes.
function with_rl(data, fn) {
	let now = NOW;
	mock.inject_all({ fs: { strict: true, data: { [rl.STATE_FILE]: '', ...(data || {}) } } }, (inj) => {
		let logs = [];
		let deps = { fs: inj.fs, native, clock: { time: () => now }, log: (l, m) => push(logs, [l, m]) };
		fn(deps, (t) => { now = t; }, inj.fs, logs);
	});
}

function state(fs) { return json(fs.readfile(rl.STATE_FILE)); }

// ─── client_key ───────────────────────────────────────────────────────────────

describe('ratelimit: client_key', () => {
	it('uses the full IPv4 address', () => {
		assert.match('v4:192.0.2.7', rl.client_key('192.0.2.7'));
		assert.match('v4:10.0.0.1', rl.client_key('10.0.0.1'));
	});

	it('maps IPv4-mapped IPv6 to the IPv4 client', () => {
		assert.match('v4:192.0.2.7', rl.client_key('::ffff:192.0.2.7'));
		assert.match('v4:192.0.2.7', rl.client_key('::FFFF:c000:207'));
	});

	it('uses the /64 of an IPv6 address, canonicalised', () => {
		assert.match('v6:2001:db8:1:2', rl.client_key('2001:db8:1:2:aaaa:bbbb:cccc:dddd'));
		assert.match('v6:2001:db8:1:2', rl.client_key('2001:0DB8:0001:0002::1'));
		assert.match('v6:2001:db8:0:0', rl.client_key('2001:db8::1'));
		assert.match('v6:0:0:0:0',      rl.client_key('::1'));
		assert.match('v6:fe80:0:0:0',   rl.client_key('fe80::1%eth0'));
		assert.match('v6:2001:db8:0:0', rl.client_key('2001:db8::'));
	});

	it('gives two addresses in one /64 the same key, and different /64s different keys', () => {
		assert.match(rl.client_key('2001:db8:5:6::1'), rl.client_key('2001:db8:5:6:ffff:ffff:ffff:ffff'));
		assert.match(true, rl.client_key('2001:db8:5:6::1') != rl.client_key('2001:db8:5:7::1'));
	});

	it('handles an embedded IPv4 tail that is not IPv4-mapped as IPv6', () => {
		assert.match('v6:64:ff9b:0:0', rl.client_key('64:ff9b::192.0.2.1'));
	});

	it('puts empty or unparseable addresses in one shared bucket', () => {
		for (let bad in [ null, '', 'localhost', '256.1.1.1', '1.2.3', '1:2:3:4:5:6:7:8:9',
		                  '1::2::3', '12345::1', 'gggg::1', '::ffff:999.1.1.1', 42, '1.2.3.4 ' ])
			assert.match(rl.UNKNOWN_CLIENT, rl.client_key(bad), `${bad}`);
	});
});

// ─── check ────────────────────────────────────────────────────────────────────

describe('ratelimit: check', () => {
	it('trips the login budget on the 11th initiation within 5 minutes', () => {
		with_rl(null, (deps, set_now) => {
			for (let i = 1; i <= rl.LIMITS.login.requests; i++) {
				set_now(NOW + i);
				assert.match(true, rl.check(deps, 'v4:192.0.2.1', true).allowed, `initiation ${i}`);
			}
			set_now(NOW + 20);
			let r = rl.check(deps, 'v4:192.0.2.1', true);
			assert.match(contains({ allowed: false, budget: 'login' }), r);
			assert.match(true, r.retry_after > 0 && r.retry_after <= rl.LIMITS.login.window);
		});
	});

	it('resets the login budget after its window', () => {
		with_rl(null, (deps, set_now) => {
			for (let i = 0; i <= rl.LIMITS.login.requests; i++) rl.check(deps, 'v4:192.0.2.1', true);
			assert.match(false, rl.check(deps, 'v4:192.0.2.1', true).allowed);
			set_now(NOW + rl.LIMITS.login.window);
			assert.match(true, rl.check(deps, 'v4:192.0.2.1', true).allowed);
		});
	});

	it('trips the general budget on the 31st request within a minute', () => {
		with_rl(null, (deps) => {
			for (let i = 1; i <= rl.LIMITS.client.requests; i++)
				assert.match(true, rl.check(deps, 'v4:192.0.2.1', false).allowed, `request ${i}`);
			assert.match(contains({ allowed: false, budget: 'client' }), rl.check(deps, 'v4:192.0.2.1', false));
		});
	});

	it('does not charge callbacks and logouts to the login budget', () => {
		with_rl(null, (deps, set_now) => {
			for (let i = 0; i < 20; i++) rl.check(deps, 'v4:192.0.2.1', false);
			assert.match(true, rl.check(deps, 'v4:192.0.2.1', true).allowed, 'login still allowed after 20 callbacks');
		});
	});

	it('gives separate clients separate budgets', () => {
		with_rl(null, (deps) => {
			for (let i = 0; i <= rl.LIMITS.login.requests; i++) rl.check(deps, 'v4:192.0.2.1', true);
			assert.match(false, rl.check(deps, 'v4:192.0.2.1', true).allowed, 'attacker is limited');
			assert.match(true, rl.check(deps, 'v4:192.0.2.2', true).allowed, 'another client is not');
		});
	});

	it('shares one budget across a /64', () => {
		with_rl(null, (deps) => {
			let a = rl.client_key('2001:db8:1:1::a'), b = rl.client_key('2001:db8:1:1::b');
			for (let i = 0; i < rl.LIMITS.login.requests; i++) rl.check(deps, a, true);
			assert.match(false, rl.check(deps, b, true).allowed);
		});
	});

	it('never stores a client address, only a 16-hex hash', () => {
		with_rl(null, (deps, set_now, fs) => {
			rl.check(deps, 'v4:192.0.2.1', true);
			let raw = fs.readfile(rl.STATE_FILE);
			assert.match(-1, index(raw, '192.0.2.1'));
			for (let k in keys(state(fs))) assert.match(true, match(k, /^[0-9a-f]{16}$/) != null, k);
		});
	});

	it('keeps at most LIMIT_TRACKED_CLIENTS entries, dropping the least recently seen', () => {
		with_rl(null, (deps, set_now, fs) => {
			// All inside one minute, so pruning keeps every window live: only the
			// cap can drop entries. Clients 0-9 share the oldest second.
			for (let i = 0; i < rl.LIMITS.tracked + 10; i++) {
				set_now(NOW + int(i / 10));
				rl.check(deps, sprintf('v4:10.0.%d.%d', i >> 8, i & 255), false);
			}
			let s = state(fs);
			assert.match(rl.LIMITS.tracked, length(keys(s)));
			let oldest = 1e12;
			for (let k, e in s) if (e.seen < oldest) oldest = e.seen;
			assert.match(NOW + 1, oldest, 'the 10 clients seen first were dropped');
		});
	});

	it('prunes clients whose windows have all ended', () => {
		with_rl(null, (deps, set_now, fs) => {
			rl.check(deps, 'v4:192.0.2.1', false);
			set_now(NOW + rl.LIMITS.client.window + 1);
			rl.check(deps, 'v4:192.0.2.2', false);
			assert.match(1, length(keys(state(fs))));
		});
	});

	it('recovers from a corrupt state file and logs it', () => {
		with_rl({ [rl.STATE_FILE]: '{ not json' }, (deps, set_now, fs, logs) => {
			assert.match(true, rl.check(deps, 'v4:192.0.2.1', true).allowed);
			assert.match(1, length(keys(state(fs))));
			assert.match(1, length(filter(logs, (l) => index(l[1], 'corrupt') >= 0)));
		});
	});

	it('writes through a uniquely named temporary file and an atomic rename', () => {
		with_rl(null, (deps, set_now, fs) => {
			rl.check(deps, 'v4:192.0.2.1', false);
			rl.check(deps, 'v4:192.0.2.1', false);
			let tmps = map(spy(fs).calls.writefile, (c) => c[0]);
			assert.match(2, length(tmps));
			assert.match(true, tmps[0] != tmps[1], 'each writer has its own tmp file');
			for (let c in spy(fs).calls.rename) {
				assert.match(true, match(c[0], /^\/var\/run\/luci-sso\/ratelimit\.json\.[A-Za-z0-9_-]+\.tmp$/) != null, c[0]);
				assert.match(rl.STATE_FILE, c[1]);
			}
		});
	});
});
