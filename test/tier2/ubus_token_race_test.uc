import { it, assert, truthy, falsy } from 'utest';
import * as ubus from 'luci_sso.ubus';
import { with_context } from 'context';

// =============================================================================
// Tier 2: Token Registry Race Condition & Persistence
// =============================================================================

it('ubus: register_token - handles concurrent registration (replay)', () => {
	let token = "some-access-token-12345";
	let mkdir_mode = "allow_all";

	with_context({
		fs: {
			data: {},
			behavior: {
				mkdir: (path, mode) => {
					if (mkdir_mode == "allow_all") return true;
					// Simulate: base tokens/ dir exists, but token lock fails
					if (match(path, /tokens$/)) return true;
					return false;
				}
			}
		}
	}, (deps) => {
		let res1 = ubus.register_token(deps, token);
		assert.match(truthy(), res1.ok, "First registration should succeed");

		// Switch to "lock exists" mode to simulate race
		mkdir_mode = "lock_exists";

		let res2 = ubus.register_token(deps, token);
		assert.match(falsy(), res2.ok, "Second registration MUST fail");
		assert.match("TOKEN_REPLAYED", res2.error);
	});
});

it('ubus: register_token - resilience to registry mkdir failure', () => {
	let token = "token-123";

	with_context({
		fs: {
			data: {},
			behavior: {
				mkdir: (path, mode) => {
					if (match(path, /tokens$/)) return false; // Fail base dir
					return true; // Succeed for the token lock itself
				}
			}
		}
	}, (deps) => {
		let res = ubus.register_token(deps, token);
		assert.match(truthy(), res.ok, "Should proceed if token lock succeeds despite base dir mkdir returning false (might already exist)");
	});
});
