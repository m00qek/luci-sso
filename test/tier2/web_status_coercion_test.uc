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

it('web: render - handle both string and integer status codes safely', () => {
	let out_int = capture((deps) => web.render(deps, { status: 404, headers: {}, body: "" }));
	assert.match(truthy(), index(out_int, "Status: 404 Not Found") != -1, "Integer status should map to correct message");

	let out_str = capture((deps) => web.render(deps, { status: "404", headers: {}, body: "" }));
	assert.match(truthy(), index(out_str, "Status: 404 Not Found") != -1, "String status should map to correct message");
});
