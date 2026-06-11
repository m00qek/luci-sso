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

it('web: audit reproduction - missing status codes 429 and 503', () => {
	let out_429 = capture((deps) => web.render_error(deps, "TOO_MANY_REQUESTS", 429));
	assert.match(truthy(), index(out_429, "Status: 429 Too Many Requests") != -1, "Status 429 should map to correct message, got: " + out_429);

	let out_503 = capture((deps) => web.render_error(deps, "SSO_DISABLED", 503));
	assert.match(truthy(), index(out_503, "Status: 503 Service Unavailable") != -1, "Status 503 should map to correct message, got: " + out_503);
});

it('web: audit reproduction - missing error codes in ERROR_MAP', () => {
	let out_tmr = capture((deps) => web.render_error(deps, "TOO_MANY_REQUESTS", 429));
	assert.match(truthy(), index(out_tmr, "Error: Too many requests. Please wait before trying again.") != -1, "TOO_MANY_REQUESTS error message should be present");

	let out_sd = capture((deps) => web.render_error(deps, "SSO_DISABLED", 503));
	assert.match(truthy(), index(out_sd, "Error: Single Sign-On is not enabled on this device.") != -1, "SSO_DISABLED error message should be present");

	let out_nf = capture((deps) => web.render_error(deps, "NOT_FOUND", 404));
	assert.match(truthy(), index(out_nf, "Error: The requested path was not found.") != -1, "NOT_FOUND error message should be present");
});
