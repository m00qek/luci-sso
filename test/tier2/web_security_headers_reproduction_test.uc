'use strict';

import { it, assert, truthy } from 'utest';
import * as web from 'luci_sso.web';

function capture(fn) {
	let buf = '';
	let deps = {
		getenv: () => null,
		stdout: { write: (s) => { buf += s; }, flush: () => {} },
		log: () => {}
	};
	fn(deps);
	return buf;
}

it('web: security - reproduction of missing cache/referrer headers', () => {
	let out = capture((deps) => web.render(deps, { status: 200, body: "OK" }));

	assert.match(truthy(), index(out, "Cache-Control: no-store") >= 0, "MISSING Cache-Control: no-store HEADER");
	assert.match(truthy(), index(out, "Referrer-Policy: no-referrer") >= 0, "MISSING Referrer-Policy: no-referrer HEADER");
});

it('web: security - prevent CRLF injection in headers (W4)', () => {
	let stdout = capture((deps) => {
		let res = {
			status: 302,
			headers: {
				"Location": "https://idp.com/\r\nSet-Cookie: evil=true",
				"X-Custom": "valid\nmalicious"
			}
		};
		web.render(deps, res);
	});

	assert.match(truthy(), index(stdout, "https://idp.com/  Set-Cookie: evil=true") != -1 ||
	       index(stdout, "https://idp.com/ Set-Cookie: evil=true") != -1,
	       "CRLF MUST be sanitized in Location header");

	assert.match(truthy(), index(stdout, "X-Custom: valid malicious") != -1, "LF MUST be sanitized in custom headers");

	assert.match(-1, index(stdout, "\nSet-Cookie: evil=true\n"), "Injection attack MUST fail");
});
