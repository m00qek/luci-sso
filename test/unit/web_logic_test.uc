import { assert, assert_eq, when, then } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

when("rendering a standardized error", () => {
	mock.create().spy((io) => {
		web.render_error(io, "STATE_CORRUPTED", 401);
		let out = io.__state__.stdout_buf;
		
		then("it should return a generic message to the user", () => {
			assert(index(out, "Authentication failed") >= 0);
			assert(index(out, "STATE_CORRUPTED") == -1); // No leakage
		});

		then("it should log the specific internal code", () => {
			let found_log = false;
			for (let e in io.__state__.history) {
				if (e.type == "log" && index(e.args[1], "STATE_CORRUPTED") >= 0) {
					found_log = true;
					break;
				}
			}
			assert(found_log, "Should have logged the internal error code");
		});
	});
});

when("parsing cookies with standard formatting", () => {
	let c = web.parse_cookies("foo=bar; baz=qux");
	assert_eq(c.foo, "bar");
	assert_eq(c.baz, "qux");
});

when("parsing parameters from a query string", () => {
	let p = web.parse_params("a=1&b=2%203");
	assert_eq(p.a, "1");
	assert_eq(p.b, "2 3");
});
