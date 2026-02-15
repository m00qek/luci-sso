'use strict';

import { test, assert } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

test('web: security - reproduction of missing cache/referrer headers', () => {
	let res = { status: 200, body: "OK" };
	mock.create().spy((io) => {
		web.render(io, res);
		let out = io.__state__.stdout_buf;

		assert(index(out, "Cache-Control: no-store") >= 0, "MISSING Cache-Control: no-store HEADER");
		assert(index(out, "Referrer-Policy: no-referrer") >= 0, "MISSING Referrer-Policy: no-referrer HEADER");
	});
});

test('web: security - prevent CRLF injection in headers (W4)', () => {
	let factory = mock.create();

	let stdout = factory.get_stdout((io) => {
		let res = {
			status: 302,
			headers: {
				"Location": "https://idp.com/\r\nSet-Cookie: evil=true",
				"X-Custom": "valid\nmalicious"
			}
		};
		web.render(io, res);
	});

	// Check that CRLF was replaced by space
	assert(index(stdout, "https://idp.com/  Set-Cookie: evil=true") != -1 || 
	       index(stdout, "https://idp.com/ Set-Cookie: evil=true") != -1, 
	       "CRLF MUST be sanitized in Location header");

	assert(index(stdout, "X-Custom: valid malicious") != -1, "LF MUST be sanitized in custom headers");

	// Ensure no raw Set-Cookie: evil=true exists as a header line
	assert(index(stdout, "\nSet-Cookie: evil=true\n") == -1, "Injection attack MUST fail");
});
