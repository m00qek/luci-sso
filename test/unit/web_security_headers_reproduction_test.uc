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
