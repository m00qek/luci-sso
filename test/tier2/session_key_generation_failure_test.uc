import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: reproduction - null key propagation on generation failure (B5)', () => {
	let factory = mock.create();
	
	factory.with_env({}, (io) => {
		// 1. Force key generation path (file missing)
		io.read_file = (path) => null;
		
		// 2. Allow lock acquisition
		io.mkdir = (path) => true;
		
		// 3. Fail during the "generation/write" block
		// We mock chmod to throw, which triggers the catch(e) block in session.uc
		io.chmod = (path, mode) => {
			die("Permission denied (Mocked)");
		};

		// Execute
		let res = session.get_secret_key(io);

		// Assert
		// The bug is that it returns Result.ok(null)
		// The fix ensures it returns Result.err("SYSTEM_KEY_GENERATION_FAILED")
		
		if (res.ok && res.data === null) {
			// Print explicit failure message for the log
			print("FAIL: Reproduced B5 - get_secret_key returned Result.ok(null)
");
		}

		assert(!res.ok, "Should return error when key generation fails");
		assert(res.error == "SYSTEM_KEY_GENERATION_FAILED" || res.error == "SYSTEM_KEY_WRITE_FAILED", "Expected key generation or write failure error");
	});
});
