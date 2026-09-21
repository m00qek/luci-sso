import { describe, it, assert, contains, mock } from 'utest';
import * as http_client from 'luci_sso.components.http_client';

const URL = 'https://example.com/api';

/**
 * behavior keys:
 *   alloc_fail  – uclient.new() returns null
 *   ssl_init    – false → ssl_init() returns false
 *   connect     – false → connect() returns false
 *   request     – false → request() returns false
 *   status      – HTTP status code (default 200)
 *   body        – response body string (default '')
 *   invalid_data – true → con.read() returns an integer (triggers INVALID_DATA_TYPE)
 *   net_error   – error code passed to the error callback
 *   fs_lsdir    – behavior fn for fs.lsdir
 *   fs_access   – behavior fn for fs.access
 */
function with_http_suite(behavior, cb) {
	behavior = behavior || {};
	let ssl_opts_captured = null;

	let uclient_beh = {
		ssl_init: (opts) => { ssl_opts_captured = opts; return behavior.ssl_init !== false; },
	};
	if (behavior.connect === false) uclient_beh.connect = () => false;
	if (behavior.request === false) uclient_beh.request = () => false;
	if (behavior.alloc_fail)       uclient_beh['new']  = () => null;
	if (behavior.invalid_data) {
		let first = true;
		uclient_beh.read = () => { if (first) { first = false; return 42; } return null; };
	}

	let uclient_data = {};
	if (!behavior.alloc_fail) {
		if (behavior.net_error) {
			uclient_data[URL] = { error: behavior.net_error, body: null };
		} else {
			uclient_data[URL] = {
				status: behavior.status || 200,
				body:   (behavior.body != null) ? behavior.body : '',
			};
		}
	}

	let fs_beh = {};
	// get_system_ca_files() always lists /etc/ssl/certs. utest >= 1.5.0 dies in
	// strict mode on lsdir() for a directory the mock has never seen, so default
	// it to an empty listing the same way access defaults to false.
	fs_beh.lsdir  = behavior.fs_lsdir  || (() => []);
	fs_beh.access = behavior.fs_access || (() => false);

	mock.inject_all({
		uclient: { strict: true, data: uclient_data, behavior: uclient_beh },
		uloop:   { strict: true },
		fs:      { strict: true, behavior: fs_beh },
	}, (deps) => {
		cb(http_client.create(deps.uclient, deps.uloop, deps.fs), () => ssl_opts_captured);
	});
}

// ─── HTTPS enforcement ────────────────────────────────────────────────────────

describe('components.http_client: HTTPS enforcement', () => {
	it('get returns HTTPS_REQUIRED for http:// URL', () => {
		with_http_suite({}, (client) => {
			assert.match(contains({ ok: false, error: 'HTTPS_REQUIRED' }),
				client.get('http://example.com/api', {}));
		});
	});

	it('post returns HTTPS_REQUIRED for http:// URL', () => {
		with_http_suite({}, (client) => {
			assert.match(contains({ ok: false, error: 'HTTPS_REQUIRED' }),
				client.post('http://example.com/api', {}));
		});
	});
});

// ─── connection failures ──────────────────────────────────────────────────────

describe('components.http_client: connection failures', () => {
	it('returns HTTP_REQUEST_FAILED when uclient allocation fails', () => {
		with_http_suite({ alloc_fail: true }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});

	it('returns HTTP_REQUEST_FAILED when ssl_init fails', () => {
		with_http_suite({ ssl_init: false }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});

	it('returns HTTP_REQUEST_FAILED when connect fails', () => {
		with_http_suite({ connect: false }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});

	it('returns HTTP_REQUEST_FAILED when request fails', () => {
		with_http_suite({ request: false }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});
});

// ─── successful requests ──────────────────────────────────────────────────────

describe('components.http_client: successful requests', () => {
	it('get returns ok with status and body', () => {
		with_http_suite({ status: 200, body: '{"ok":true}' }, (client) => {
			assert.match(contains({ ok: true, data: { status: 200, body: '{"ok":true}' } }),
				client.get(URL, {}));
		});
	});

	it('post returns ok with status and body', () => {
		with_http_suite({ status: 201, body: 'created' }, (client) => {
			assert.match(contains({ ok: true, data: { status: 201, body: 'created' } }),
				client.post(URL, { body: 'payload' }));
		});
	});
});

// ─── error handling ───────────────────────────────────────────────────────────

describe('components.http_client: error handling', () => {
	it('returns HTTP_REQUEST_FAILED on network error from uclient', () => {
		with_http_suite({ net_error: '5' }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});

	it('returns HTTP_REQUEST_FAILED when response body exceeds 256 KB', () => {
		let s = 'a';
		while (length(s) < 262145) s += s;
		s = substr(s, 0, 262145);
		with_http_suite({ body: s }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});

	it('returns HTTP_REQUEST_FAILED for non-string data chunk from uclient', () => {
		with_http_suite({ invalid_data: true }, (client) => {
			assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
				client.get(URL, {}));
		});
	});
});

// ─── CA file discovery ────────────────────────────────────────────────────────

describe('components.http_client: CA file discovery', () => {
	function ca_files_for(lsdir, access) {
		let result = null;
		with_http_suite({ fs_lsdir: lsdir, fs_access: access }, (client, ssl_opts) => {
			client.get(URL, {});
			result = ssl_opts().ca_files;
		});
		return result;
	}

	function includes(arr, val) {
		for (let item in arr) if (item === val) return true;
		return false;
	}

	it('includes .crt and .pem files from /etc/ssl/certs/', () => {
		let files = ca_files_for(
			() => ['server.crt', 'chain.pem', 'readme.txt'],
			() => false
		);
		assert.match(true,  includes(files, '/etc/ssl/certs/server.crt'));
		assert.match(true,  includes(files, '/etc/ssl/certs/chain.pem'));
		assert.match(false, includes(files, '/etc/ssl/certs/readme.txt'));
	});

	it('includes well-known fallback paths when they exist', () => {
		let files = ca_files_for(
			() => null,
			(path) => path === '/etc/ssl/cert.pem'
		);
		assert.match(true, includes(files, '/etc/ssl/cert.pem'));
		assert.match(1, length(files));
	});

	it('deduplicates a file that appears in both the directory listing and well-known paths', () => {
		let files = ca_files_for(
			() => ['ca-certificates.crt'],
			(path) => path === '/etc/ssl/certs/ca-certificates.crt'
		);
		let count = 0;
		for (let f in files) if (f === '/etc/ssl/certs/ca-certificates.crt') count++;
		assert.match(1, count);
	});
});
