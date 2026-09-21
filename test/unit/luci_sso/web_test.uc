import { describe, it, prop, gen, assert, contains, is_type, truthy, falsy } from 'utest';
import * as web from 'luci_sso.web';

// web.uc is a deps-isolable leaf. Its I/O surface (getenv / stdout / log) is a
// plain CGI interface passed as an argument — not a proxied module — so tests
// drive it with a capture-deps that records written bytes and log lines.
function web_deps(env_map) {
	let buf = '';
	let logs = [];
	return {
		getenv:  (k) => (env_map && env_map[k] != null) ? env_map[k] : null,
		stdout:  { write: (s) => { buf += s; }, flush: () => {} },
		log:     (l, m) => push(logs, [l, m]),
		out:     () => buf,
		logs:    () => logs,
	};
}

// ─── parse_params ────────────────────────────────────────────────────────────

describe('web: parse_params', () => {
	it('returns empty object for null', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(null));
	});

	it('returns empty object for non-string input', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(42));
	});

	it('returns empty object for empty string', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(''));
	});

	it('parses a single key=value pair', () => {
		assert.match(contains({ ok: true, data: { a: '1' } }), web.parse_params('a=1'));
	});

	it('parses multiple pairs', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_params('a=1&b=2'));
	});

	it('stores null for a key with no = separator', () => {
		assert.match(contains({ ok: true, data: { a: null } }), web.parse_params('a'));
	});

	it('stores empty string for a key with trailing =', () => {
		assert.match(contains({ ok: true, data: { a: '' } }), web.parse_params('a='));
	});

	it('decodes + as space', () => {
		assert.match(contains({ ok: true, data: { a: 'hello world' } }), web.parse_params('a=hello+world'));
	});

	it('decodes percent-encoded characters', () => {
		assert.match(contains({ ok: true, data: { a: 'hello world' } }), web.parse_params('a=hello%20world'));
	});

	it('returns INPUT_TOO_LARGE for a string exceeding 16384 characters', () => {
		let big = '';
		for (let i = 0; i < 17; i++)
			big += 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 1000 chars × 17 = 17000 > 16384
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_params(big));
	});

	it('returns INPUT_TOO_LARGE for more than 100 pairs', () => {
		let pairs = [];
		for (let i = 0; i < 101; i++) push(pairs, `p${i}=v`);
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_params(join('&', pairs)));
	});

	prop('never throws and always returns a Result for any ASCII input',
		gen.ascii({ max_len: 300 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) == 0);
			ctx.classify('contains =', index(s, '=') >= 0);
			assert.match(contains({ ok: is_type('bool') }), web.parse_params(s));
		}
	);
});

// ─── parse_cookies ───────────────────────────────────────────────────────────

describe('web: parse_cookies', () => {
	it('returns empty object for null', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(null));
	});

	it('returns empty object for non-string input', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(42));
	});

	it('returns empty object for empty string', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(''));
	});

	it('parses a single name=value pair', () => {
		assert.match(contains({ ok: true, data: { a: '1' } }), web.parse_cookies('a=1'));
	});

	it('parses multiple pairs separated by "; "', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_cookies('a=1; b=2'));
	});

	it('parses multiple pairs with no space after semicolon', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_cookies('a=1;b=2'));
	});

	it('strips double-quotes from quoted values', () => {
		assert.match(contains({ ok: true, data: { session: 'abc123' } }), web.parse_cookies('session="abc123"'));
	});

	it('stores empty string for a cookie with no value', () => {
		assert.match(contains({ ok: true, data: { a: '' } }), web.parse_cookies('a='));
	});

	it('returns INPUT_TOO_LARGE for a string exceeding 16384 characters', () => {
		let big = '';
		for (let i = 0; i < 17; i++)
			big += 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_cookies(big));
	});

	it('returns INPUT_TOO_LARGE for more than 100 pairs', () => {
		let pairs = [];
		for (let i = 0; i < 101; i++) push(pairs, `c${i}=v`);
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_cookies(join('; ', pairs)));
	});

	prop('never throws and always returns a Result for any ASCII input',
		gen.ascii({ max_len: 300 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) == 0);
			ctx.classify('contains ;', index(s, ';') >= 0);
			assert.match(contains({ ok: is_type('bool') }), web.parse_cookies(s));
		}
	);
});

// ─── render ───────────────────────────────────────────────────────────────────

describe('web: render', () => {
	it('maps both integer and string status codes to the correct reason phrase', () => {
		let d1 = web_deps({}); web.render(d1, { status: 404, headers: {}, body: "" });
		assert.match(truthy(), index(d1.out(), "Status: 404 Not Found") != -1, "Integer status should map to correct message");

		let d2 = web_deps({}); web.render(d2, { status: "404", headers: {}, body: "" });
		assert.match(truthy(), index(d2.out(), "Status: 404 Not Found") != -1, "String status should map to correct message");
	});

	it('emits hardened security headers', () => {
		let d = web_deps({});
		web.render(d, { status: 200, body: "OK" });
		let out = d.out();
		assert.match(truthy(), index(out, "Content-Security-Policy:") >= 0, "MISSING CSP HEADER");
		assert.match(truthy(), index(out, "X-Content-Type-Options: nosniff") >= 0, "MISSING nosniff HEADER");
		assert.match(truthy(), index(out, "X-Frame-Options: DENY") >= 0, "MISSING Frame-Options HEADER");
		assert.match(truthy(), index(out, "Cache-Control: no-store") >= 0, "MISSING Cache-Control: no-store HEADER");
		assert.match(truthy(), index(out, "Referrer-Policy: no-referrer") >= 0, "MISSING Referrer-Policy: no-referrer HEADER");
	});

	it('keeps a redirect Location unescaped in the header but out of the HTML body (XSS)', () => {
		let malicious_loc = 'javascript:alert("XSS")//"><img src=x onerror=alert(1)>';
		let d = web_deps({});
		web.render(d, { status: 302, headers: { "Location": malicious_loc } });
		let out = d.out();

		assert.match(truthy(), index(out, `Location: ${malicious_loc}\n`) >= 0, "Location header should be unescaped for HTTP");

		let parts = split(out, "\n\n", 2);
		let body = parts[1] || "";
		assert.match(truthy(), index(body, "Redirecting") >= 0, "Should contain redirecting message");
		assert.match(-1, index(body, malicious_loc), "Malicious location MUST NOT be present in HTML body");
		assert.match(-1, index(body, "url="), "Meta refresh URL MUST NOT be present in body");
	});

	it('sanitizes CRLF injection in header values (W4)', () => {
		let d = web_deps({});
		web.render(d, {
			status: 302,
			headers: {
				"Location": "https://idp.com/\r\nSet-Cookie: evil=true",
				"X-Custom": "valid\nmalicious"
			}
		});
		let out = d.out();

		assert.match(truthy(), index(out, "https://idp.com/  Set-Cookie: evil=true") != -1 ||
		       index(out, "https://idp.com/ Set-Cookie: evil=true") != -1,
		       "CRLF MUST be sanitized in Location header");
		assert.match(truthy(), index(out, "X-Custom: valid malicious") != -1, "LF MUST be sanitized in custom headers");
		assert.match(-1, index(out, "\nSet-Cookie: evil=true\n"), "Injection attack MUST fail");
	});
});

// ─── render_error ──────────────────────────────────────────────────────────────

describe('web: render_error', () => {
	it('returns a generic message, never leaks the internal code, and audit-logs it', () => {
		let d = web_deps({});
		web.render_error(d, "STATE_CORRUPTED", 401);
		let out = d.out();

		assert.match(truthy(), index(out, "Authentication failed") >= 0, "Should return generic message");
		assert.match(-1, index(out, "STATE_CORRUPTED"), "Internal codes MUST NOT leak to body");

		let found_log = false;
		for (let e in d.logs()) {
			if (e[1] && index(e[1], "STATE_CORRUPTED") >= 0) { found_log = true; break; }
		}
		assert.match(truthy(), found_log, "Should have logged the internal error code for admin audit");
	});

	it('emits the 431 status with a user-friendly message', () => {
		let d = web_deps({});
		web.render_error(d, "INPUT_TOO_LARGE", 431);
		let out = d.out();
		assert.match(truthy(), index(out, "Status: 431 Request Header Fields Too Large") >= 0, "Should emit 431 status");
		assert.match(truthy(), index(out, "too much data") >= 0, "Should contain user-friendly error message");
	});

	it('maps the 429 and 503 statuses to their reason phrases', () => {
		let d1 = web_deps({}); web.render_error(d1, "TOO_MANY_REQUESTS", 429);
		assert.match(truthy(), index(d1.out(), "Status: 429 Too Many Requests") != -1, "Status 429 should map to correct message");

		let d2 = web_deps({}); web.render_error(d2, "SSO_DISABLED", 503);
		assert.match(truthy(), index(d2.out(), "Status: 503 Service Unavailable") != -1, "Status 503 should map to correct message");
	});

	it('renders user-facing messages for known error codes', () => {
		let d1 = web_deps({}); web.render_error(d1, "TOO_MANY_REQUESTS", 429);
		assert.match(truthy(), index(d1.out(), "Error: Too many requests. Please wait before trying again.") != -1, "TOO_MANY_REQUESTS message");

		let d2 = web_deps({}); web.render_error(d2, "SSO_DISABLED", 503);
		assert.match(truthy(), index(d2.out(), "Error: Single Sign-On is not enabled on this device.") != -1, "SSO_DISABLED message");

		let d3 = web_deps({}); web.render_error(d3, "NOT_FOUND", 404);
		assert.match(truthy(), index(d3.out(), "Error: The requested path was not found.") != -1, "NOT_FOUND message");
	});
});

// ─── request ───────────────────────────────────────────────────────────────────

describe('web: request', () => {
	it('returns INPUT_TOO_LARGE when an environment value overflows', () => {
		let long_val = "";
		for (let i = 0; i < 16385; i++) long_val += "a";

		let d = web_deps({ "HTTP_HOST": long_val });
		let res = web.request(d);
		assert.match(falsy(), res.ok, "Should fail on overflow");
		assert.match("INPUT_TOO_LARGE", res.error);
	});
});
