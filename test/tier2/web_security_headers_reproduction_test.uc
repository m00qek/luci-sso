'use strict';

import { it, assert, truthy } from 'utest';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

function make_web_deps(io) {
	return {
		getenv: (k)    => io.getenv(k),
		stdout: io.stdout,
		log:    (l, m) => io.log(l, m)
	};
}

it('web: security - reproduction of missing cache/referrer headers', () => {
	let res = { status: 200, body: "OK" };
	mock.create().spy((io) => {
		web.render(make_web_deps(io), res);
		let out = io.__state__.stdout_buf;

		assert.match(truthy(), index(out, "Cache-Control: no-store") >= 0, "MISSING Cache-Control: no-store HEADER");
		assert.match(truthy(), index(out, "Referrer-Policy: no-referrer") >= 0, "MISSING Referrer-Policy: no-referrer HEADER");
	});
});

it('web: security - prevent CRLF injection in headers (W4)', () => {
	let factory = mock.create();

	let stdout = factory.get_stdout((io) => {
		let res = {
			status: 302,
			headers: {
				"Location": "https://idp.com/\r\nSet-Cookie: evil=true",
				"X-Custom": "valid\nmalicious"
			}
		};
		web.render(make_web_deps(io), res);
	});

	// Check that CRLF was replaced by space
	assert.match(truthy(), index(stdout, "https://idp.com/  Set-Cookie: evil=true") != -1 || 
	       index(stdout, "https://idp.com/ Set-Cookie: evil=true") != -1, 
	       "CRLF MUST be sanitized in Location header");

	assert.match(truthy(), index(stdout, "X-Custom: valid malicious") != -1, "LF MUST be sanitized in custom headers");

	// Ensure no raw Set-Cookie: evil=true exists as a header line
	assert.match(-1, index(stdout, "\nSet-Cookie: evil=true\n"), "Injection attack MUST fail");
});
