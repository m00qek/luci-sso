import { it, assert, truthy } from 'utest';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

it('web: rendering - standardized error prevents internal leakage', () => {
	mock.create().spy((io) => {
		web.render_error(io, "STATE_CORRUPTED", 401);
		let out = io.__state__.stdout_buf;

		assert.match(truthy(), index(out, "Authentication failed") >= 0, "Should return generic message");
		assert.match(truthy(), index(out, "STATE_CORRUPTED") == -1, "Internal codes MUST NOT leak to body");

		let found_log = false;
		for (let e in io.__state__.history) {
			if (e.type == "log" && index(e.args[1], "STATE_CORRUPTED") >= 0) {
				found_log = true;
				break;
			}
		}
		assert.match(truthy(), found_log, "Should have logged the internal error code for admin audit");
	});
});

it('web: parsing - standard cookie format', () => {
	let res = web.parse_cookies("foo=bar; baz=qux");
	assert.match(truthy(), res.ok);
	assert.match("bar", res.data.foo);
	assert.match("qux", res.data.baz);
});

it('web: parsing - standard query parameters', () => {
	let res = web.parse_params("a=1&b=2%203");
	assert.match(truthy(), res.ok);
	assert.match("1", res.data.a);
	assert.match("2 3", res.data.b);
});

it('web: security - prevent XSS in redirect location', () => {
	let malicious_loc = 'javascript:alert("XSS")//"><img src=x onerror=alert(1)>';
	let res = {
		status: 302,
		headers: { "Location": malicious_loc }
	};

	mock.create().spy((io) => {
		web.render(io, res);
		let out = io.__state__.stdout_buf;

		// 1. Verify Header is correct (Unescaped for protocol)
		assert.match(truthy(), index(out, `Location: ${malicious_loc}\n`) >= 0, "Location header should be unescaped for HTTP");

		// 2. Verify Body is generic and contains NO location strings
		let parts = split(out, "\n\n", 2);
		let body = parts[1] || "";

		assert.match(truthy(), index(body, "Redirecting") >= 0, "Should contain redirecting message");
		assert.match(truthy(), index(body, malicious_loc) == -1, "Malicious location MUST NOT be present in HTML body");
		assert.match(truthy(), index(body, "url=") == -1, "Meta refresh URL MUST NOT be present in body");
	});
});

it('web: security - safe_getenv returns Result.err on overflow', () => {
	let long_val = "";
	for (let i = 0; i < 16385; i++) long_val += "a";

	mock.create().with_env({ "HTTP_HOST": long_val }, (io) => {
		let res = web.request(io);
		assert.match(truthy(), !res.ok, "Should fail on overflow");
		assert.match("INPUT_TOO_LARGE", res.error);
	});
});

it('web: security - parse_params returns Result.err on overflow', () => {
	let long_val = "";
	for (let i = 0; i < 16385; i++) long_val += "a";

	let res = web.parse_params(long_val);
	assert.match(truthy(), !res.ok, "Should fail on overflow");
	assert.match("INPUT_TOO_LARGE", res.error);
});

it('web: security - parse_params rejects too many parameters', () => {
	let params = [];
	for (let i = 0; i < 101; i++) push(params, `p${i}=v${i}`);
	let res = web.parse_params(join("&", params));

	assert.match(truthy(), !res.ok, "Should fail on too many parameters");
	assert.match("INPUT_TOO_LARGE", res.error);
	assert.match(431, res.details.http_status);
});

it('web: security - render_error emits 431 when requested', () => {
	mock.create().spy((io) => {
		web.render_error(io, "INPUT_TOO_LARGE", 431);
		let out = io.__state__.stdout_buf;
		assert.match(truthy(), index(out, "Status: 431 Request Header Fields Too Large") >= 0, "Should emit 431 status");
		assert.match(truthy(), index(out, "too much data") >= 0, "Should contain user-friendly error message");
	});
});

it('web: security - emission of hardened security headers', () => {
	let res = { status: 200, body: "OK" };
	mock.create().spy((io) => {
		web.render(io, res);
		let out = io.__state__.stdout_buf;

		assert.match(truthy(), index(out, "Content-Security-Policy:") >= 0, "MISSING CSP HEADER");
		assert.match(truthy(), index(out, "X-Content-Type-Options: nosniff") >= 0, "MISSING nosniff HEADER");
		assert.match(truthy(), index(out, "X-Frame-Options: DENY") >= 0, "MISSING Frame-Options HEADER");
	});
});
