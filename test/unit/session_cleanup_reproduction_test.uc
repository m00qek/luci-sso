import { test, assert } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: reproduction - verify_state cleanup failure on read error (W5)', () => {
	let handle = "repro-W5";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	let consume_path = `${path}.consumed`;

	let factory = mock.create();
	
	// Create the initial file
	factory.with_files({ [path]: "{}" }, (io) => {
		// Mock read_file to simulate I/O error or empty read AFTER rename
		io.read_file = (f) => {
			if (f == consume_path) return null; // Simulate empty/error
			return "{}";
		};

		// Spy on remove
		let remove_called = false;
		let original_remove = io.remove;
		io.remove = (f) => {
			if (f == consume_path) remove_called = true;
			return original_remove(f);
		};

		let res = session.verify_state(io, handle, 300);

		// Assertions
		assert(!res.ok, "Should fail due to read error");
		assert(remove_called, "CRITICAL: Must remove .consumed file even if read fails");
	});
});
