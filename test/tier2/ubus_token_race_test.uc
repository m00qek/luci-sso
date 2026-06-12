import { describe, it, assert, truthy, falsy } from 'utest';
import * as ubus from 'luci_sso.ubus';
import { with_context } from 'context';

describe('ubus: register_token', () => {
	it('handles concurrent registration (replay)', () => {
		let token = "some-access-token-12345";
		let mkdir_mode = "allow_all";

		with_context({
			fs: {
				data: {},
				behavior: {
					mkdir: (path, mode) => {
						if (mkdir_mode == "allow_all") return true;
						if (match(path, /tokens$/)) return true;
						return false;
					}
				}
			}
		}, (deps) => {
			let res1 = ubus.register_token(deps, token);
			assert.match(truthy(), res1.ok, "First registration should succeed");

			mkdir_mode = "lock_exists";

			let res2 = ubus.register_token(deps, token);
			assert.match(falsy(), res2.ok, "Second registration MUST fail");
			assert.match("TOKEN_REPLAYED", res2.error);
		});
	});

	it('resilience to registry mkdir failure', () => {
		let token = "token-123";

		with_context({
			fs: {
				data: {},
				behavior: {
					mkdir: (path, mode) => {
						if (match(path, /tokens$/)) return false;
						return true;
					}
				}
			}
		}, (deps) => {
			let res = ubus.register_token(deps, token);
			assert.match(truthy(), res.ok, "Should proceed if token lock succeeds despite base dir mkdir returning false (might already exist)");
		});
	});
});
