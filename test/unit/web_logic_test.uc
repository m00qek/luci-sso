import { test, assert, assert_eq } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

test('web: rendering - standardized error prevents internal leakage', () => {
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

test('web: parsing - standard cookie format', () => {
	let c = web.parse_cookies("foo=bar; baz=qux");
	assert_eq(c.foo, "bar");
	assert_eq(c.baz, "qux");
});

test('web: parsing - standard query parameters', () => {
	let p = web.parse_params("a=1&b=2%203");
	assert_eq(p.a, "1");
	assert_eq(p.b, "2 3");
});

test('web: security - prevent XSS in redirect location', () => {
	let malicious_loc = 'javascript:alert("XSS")//"><img src=x onerror=alert(1)>';
	let res = {
		status: 302,
		headers: { "Location": malicious_loc }
	};

	mock.create().spy((io) => {
		web.render(io, res);
		let out = io.__state__.stdout_buf;
		
		// 1. Verify Header is correct (Unescaped for protocol)
		assert(index(out, `Location: ${malicious_loc}\n`) >= 0, "Location header should be unescaped for HTTP");

		// 2. Verify Body is escaped (everything after \n\n)
		let parts = split(out, "\n\n", 2);
		let body = parts[1] || "";
		
		assert(index(body, malicious_loc) == -1, "Raw malicious location MUST NOT be present in HTML body");
		assert(index(body, 'alert(&quot;XSS&quot;)') >= 0 || index(body, 'alert(&#x27;XSS&#x27;)') >= 0, "Location MUST be HTML escaped in body");
	});
});

test('web: security - emission of hardened security headers', () => {
	let res = { status: 200, body: "OK" };
	mock.create().spy((io) => {
		web.render(io, res);
		let out = io.__state__.stdout_buf;
		
		assert(index(out, "Content-Security-Policy:") >= 0, "MISSING CSP HEADER");
		assert(index(out, "X-Content-Type-Options: nosniff") >= 0, "MISSING nosniff HEADER");
		assert(index(out, "X-Frame-Options: DENY") >= 0, "MISSING Frame-Options HEADER");
	});
});
