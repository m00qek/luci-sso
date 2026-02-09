import { test, assert, assert_eq } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

test('Web: Rendering - Standardized error prevents internal leakage', () => {
	mock.create().spy((io) => {
		web.render_error(io, "STATE_CORRUPTED", 401);
		let out = io.__state__.stdout_buf;
		
		assert(index(out, "Authentication failed") >= 0, "Should return generic message");
		assert(index(out, "STATE_CORRUPTED") == -1, "Internal codes MUST NOT leak to body");

		let found_log = false;
		for (let e in io.__state__.history) {
			if (e.type == "log" && index(e.args[1], "STATE_CORRUPTED") >= 0) {
				found_log = true;
				break;
			}
		}
		assert(found_log, "Should have logged the internal error code for admin audit");
	});
});

test('Web: Parsing - Standard cookie format', () => {
	let c = web.parse_cookies("foo=bar; baz=qux");
	assert_eq(c.foo, "bar");
	assert_eq(c.baz, "qux");
});

test('Web: Parsing - Standard query parameters', () => {
	let p = web.parse_params("a=1&b=2%203");
	assert_eq(p.a, "1");
	assert_eq(p.b, "2 3");
});