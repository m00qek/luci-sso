import { it, assert, truthy } from 'utest';
import { create } from 'luci_sso.components.clock';
import * as uloop from 'uloop';

it("clock: sleep - verify timing accuracy", () => {
	let clk = create(uloop);

	let start = clock();
	clk.sleep(0.1);
	let end = clock();

	let duration = (end[0] - start[0]) + ((end[1] - start[1]) / 1000000000.0);

	// We expect roughly 0.1s. Allow minor jitter (0.09s).
	assert.match(truthy(), duration >= 0.09, `Expected sleep for 0.1s, but got ${duration}s`);
	assert.match(truthy(), duration <= 0.2, `Expected sleep to be reasonable, but got ${duration}s`);
});

it("clock: sleep - contract violations", () => {
	let clk = create(uloop);
	assert.throws(() => clk.sleep(-0.1), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
	assert.throws(() => clk.sleep("0.1"), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
	assert.throws(() => clk.sleep(30.1), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
});
