import { describe, it, assert } from 'utest';
import * as clock from 'luci_sso.components.clock';

function make_uloop() {
	let calls     = [];
	let timer_ms  = null;
	let pending   = null;
	return {
		init:     () => push(calls, 'init'),
		timer:    (ms, cb) => { push(calls, 'timer'); timer_ms = ms; pending = cb; },
		run:      () => { push(calls, 'run'); if (pending) { let cb = pending; pending = null; cb(); } },
		end:      () => push(calls, 'end'),
		calls:    () => calls,
		timer_ms: () => timer_ms,
	};
}

// ─── time() ──────────────────────────────────────────────────────────────────

describe('components.clock: time()', () => {
	it('uses the provided time_fn', () => {
		let c = clock.create(make_uloop(), () => 42);
		assert.match(42, c.time());
	});

	it('without time_fn returns a positive integer', () => {
		let c = clock.create(make_uloop());
		let t = c.time();
		assert.match(true, type(t) === 'int' && t > 0);
	});
});

// ─── sleep() — valid inputs ───────────────────────────────────────────────────

describe('components.clock: sleep() — valid inputs', () => {
	it('invokes uloop in order: init → timer → run → end', () => {
		let ul = make_uloop();
		clock.create(ul).sleep(1);
		assert.match(['init', 'timer', 'run', 'end'], ul.calls());
	});

	it('passes seconds * 1000 as ms to uloop.timer', () => {
		let ul = make_uloop();
		clock.create(ul).sleep(2);
		assert.match(2000, ul.timer_ms());
	});

	it('accepts a double (fractional seconds) without throwing', () => {
		let ul = make_uloop();
		clock.create(ul).sleep(0.5);
		assert.match(['init', 'timer', 'run', 'end'], ul.calls());
	});

	it('accepts 0 (lower boundary)', () => {
		let ul = make_uloop();
		clock.create(ul).sleep(0);
		assert.match(0, ul.timer_ms());
	});

	it('accepts 30 (upper boundary)', () => {
		let ul = make_uloop();
		clock.create(ul).sleep(30);
		assert.match(30000, ul.timer_ms());
	});
});

// ─── sleep() — CONTRACT_VIOLATION ────────────────────────────────────────────

describe('components.clock: sleep() — CONTRACT_VIOLATION', () => {
	let c = clock.create(make_uloop());

	it('dies for null', () => {
		assert.throws(() => c.sleep(null), /CONTRACT_VIOLATION/);
	});

	it('dies for a string', () => {
		assert.throws(() => c.sleep('1'), /CONTRACT_VIOLATION/);
	});

	it('dies for a negative integer', () => {
		assert.throws(() => c.sleep(-1), /CONTRACT_VIOLATION/);
	});

	it('dies for a value above 30', () => {
		assert.throws(() => c.sleep(31), /CONTRACT_VIOLATION/);
	});

	it('dies for a negative double', () => {
		assert.throws(() => c.sleep(-0.1), /CONTRACT_VIOLATION/);
	});
});
