import { test, assert, assert_match, assert_fail } from 'testing';
import { create } from 'luci_sso.io';

test("io.sleep() - verify timing and yielding", () => {
	let io = create();
	
	let start = clock();
	io.sleep(0.1);
	let end = clock();
	
	let duration = (end[0] - start[0]) + ((end[1] - start[1]) / 1000000000.0);
	
	// We expect roughly 0.1s. Allow minor jitter (0.09s).
	assert(duration >= 0.09, `Expected sleep for 0.1s, but got ${duration}s`);
	assert(duration <= 0.2, `Expected sleep to be reasonable, but got ${duration}s`);
});

test("io.sleep() - type safety", () => {
    let io = create();
    
    // Test for negative seconds
    try {
        io.sleep(-0.1);
        assert_fail("Should have died on negative seconds");
    } catch (e) {
        assert_match(sprintf("%s", e), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
    }
    
    // Test for non-number
    try {
        io.sleep("0.1");
        assert_fail("Should have died on string input");
    } catch (e) {
        assert_match(sprintf("%s", e), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
    }

    // Test for upper bound (30s)
    try {
        io.sleep(30.1);
        assert_fail("Should have died on seconds > 30");
    } catch (e) {
        assert_match(sprintf("%s", e), /CONTRACT_VIOLATION/, "Error should mention CONTRACT_VIOLATION");
    }
});
