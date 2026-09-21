import { describe, it, prop, gen, assert, mock, spy } from 'utest';
import * as clock from 'luci_sso.components.clock';

// ─── time() ──────────────────────────────────────────────────────────────────

describe('components.clock: time()', () => {
	it('uses the provided time_fn', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.match(42, clock.create(deps.uloop, () => 42).time());
		});
	});

	it('without time_fn returns a positive integer', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			let t = clock.create(deps.uloop).time();
			assert.match(true, type(t) === 'int' && t > 0);
		});
	});
});

// ─── sleep() — valid inputs ───────────────────────────────────────────────────

describe('components.clock: sleep() — valid inputs', () => {
	it('invokes uloop in order: init → timer → run → end', () => {
		let order = [];
		let pending_cb = null;
		mock.inject_all({
			uloop: {
				strict: true,
				behavior: {
					init:  ()       => push(order, 'init'),
					timer: (ms, cb) => { push(order, 'timer'); pending_cb = cb; },
					run:   ()       => { push(order, 'run'); if (pending_cb) { pending_cb(); pending_cb = null; } },
					end:   ()       => push(order, 'end'),
				}
			}
		}, (deps) => {
			clock.create(deps.uloop).sleep(1);
			assert.match(['init', 'timer', 'run', 'end'], order);
		});
	});

	it('passes seconds * 1000 as ms to uloop.timer', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			clock.create(deps.uloop).sleep(2);
			assert.match(2000, spy(deps.uloop).calls.timer[0][0]);
		});
	});

	it('accepts a double (fractional seconds) without throwing', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			clock.create(deps.uloop).sleep(0.5);
			assert.match(1, length(spy(deps.uloop).calls.init));
		});
	});

	it('accepts 0 (lower boundary)', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			clock.create(deps.uloop).sleep(0);
			assert.match(0, spy(deps.uloop).calls.timer[0][0]);
		});
	});

	it('accepts 30 (upper boundary)', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			clock.create(deps.uloop).sleep(30);
			assert.match(30000, spy(deps.uloop).calls.timer[0][0]);
		});
	});

	prop('sleep(n) always passes n * 1000 ms to uloop.timer for any integer in [0, 30]',
		gen.int(0, 30), (n) => {
			mock.inject_all({ uloop: { strict: true } }, (deps) => {
				clock.create(deps.uloop).sleep(n);
				assert.match(n * 1000, spy(deps.uloop).calls.timer[0][0]);
			});
		}
	);
});

// ─── sleep() — CONTRACT_VIOLATION ────────────────────────────────────────────

describe('components.clock: sleep() — CONTRACT_VIOLATION', () => {
	it('dies for null', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.throws(() => clock.create(deps.uloop).sleep(null), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a string', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.throws(() => clock.create(deps.uloop).sleep('1'), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a negative integer', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.throws(() => clock.create(deps.uloop).sleep(-1), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a value above 30', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.throws(() => clock.create(deps.uloop).sleep(31), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a negative double', () => {
		mock.inject_all({ uloop: { strict: true } }, (deps) => {
			assert.throws(() => clock.create(deps.uloop).sleep(-0.1), /CONTRACT_VIOLATION/);
		});
	});
});
