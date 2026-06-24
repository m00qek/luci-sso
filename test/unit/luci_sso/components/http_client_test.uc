import { describe, it, assert, contains } from 'utest';
import * as http_client from 'luci_sso.components.http_client';

const URL = 'https://example.com/api';

/**
 * Builds a matched (uclient, uloop, fs) triple for a given scenario.
 *
 * behavior keys:
 *   alloc_fail  – uclient.new() returns null
 *   ssl_init    – false → ssl_init() returns false
 *   connect     – false → connect() returns false
 *   request     – false → request() returns false
 *   status      – HTTP status code (default 200)
 *   body        – response body string (default '')
 *   invalid_data – true → con.read() returns an integer (triggers INVALID_DATA_TYPE)
 *   net_error   – string code passed to the error callback
 *   fs_lsdir    – override for fs.lsdir (default: () => null)
 *   fs_access   – override for fs.access (default: () => false)
 */
function make_suite(behavior) {
	behavior = behavior || {};

	let captured_cb = null;
	let ssl_opts    = null;

	let read_calls = 0;
	let body_str   = (behavior.body != null) ? behavior.body : '';
	let chunks     = length(body_str) > 0 ? [body_str] : [];

	let con = {
		ssl_init:    (opts) => { ssl_opts = opts; return behavior.ssl_init !== false; },
		set_timeout: () => null,
		connect:     () => behavior.connect  !== false,
		request:     () => behavior.request  !== false,
		get_headers: () => behavior.headers  || {},
		status:      () => ({ status: behavior.status || 200 }),
		disconnect:  () => null,
		read: () => {
			if (behavior.invalid_data && read_calls === 0) { read_calls++; return 42; }
			return read_calls < length(chunks) ? chunks[read_calls++] : null;
		},
	};

	let uloop = {
		init:  () => null,
		timer: () => null,
		end:   () => null,
		run: () => {
			if (!captured_cb) return;
			if (behavior.net_error) {
				captured_cb.error(null, behavior.net_error);
			} else {
				captured_cb.header_done();
				captured_cb.data_read();
				captured_cb.data_eof();
			}
		},
	};

	let uclient = {
		new: (url, null_, callbacks) => {
			captured_cb = callbacks;
			return behavior.alloc_fail ? null : con;
		}
	};

	let fs = {
		lsdir:  behavior.fs_lsdir  || (() => null),
		access: behavior.fs_access || (() => false),
	};

	return {
		client:   http_client.create(uclient, uloop, fs),
		ssl_opts: () => ssl_opts,
	};
}

// ─── HTTPS enforcement ────────────────────────────────────────────────────────

describe('components.http_client: HTTPS enforcement', () => {
	let s = make_suite();

	it('get returns HTTPS_REQUIRED for http:// URL', () => {
		assert.match(contains({ ok: false, error: 'HTTPS_REQUIRED' }), s.client.get('http://example.com/api', {}));
	});

	it('post returns HTTPS_REQUIRED for http:// URL', () => {
		assert.match(contains({ ok: false, error: 'HTTPS_REQUIRED' }), s.client.post('http://example.com/api', {}));
	});
});

// ─── connection failures ──────────────────────────────────────────────────────

describe('components.http_client: connection failures', () => {
	it('returns HTTP_REQUEST_FAILED when uclient allocation fails', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ alloc_fail: true }).client.get(URL, {}));
	});

	it('returns HTTP_REQUEST_FAILED when ssl_init fails', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ ssl_init: false }).client.get(URL, {}));
	});

	it('returns HTTP_REQUEST_FAILED when connect fails', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ connect: false }).client.get(URL, {}));
	});

	it('returns HTTP_REQUEST_FAILED when request fails', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ request: false }).client.get(URL, {}));
	});
});

// ─── successful requests ──────────────────────────────────────────────────────

describe('components.http_client: successful requests', () => {
	it('get returns ok with status and body', () => {
		let res = make_suite({ status: 200, body: '{"ok":true}' }).client.get(URL, {});
		assert.match(contains({ ok: true, data: { status: 200, body: '{"ok":true}' } }), res);
	});

	it('post returns ok with status and body', () => {
		let res = make_suite({ status: 201, body: 'created' }).client.post(URL, { body: 'payload' });
		assert.match(contains({ ok: true, data: { status: 201, body: 'created' } }), res);
	});
});

// ─── error handling ───────────────────────────────────────────────────────────

describe('components.http_client: error handling', () => {
	it('returns HTTP_REQUEST_FAILED on network error from uclient', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ net_error: '5' }).client.get(URL, {}));
	});

	it('returns HTTP_REQUEST_FAILED when response body exceeds 256 KB', () => {
		let s = 'a';
		while (length(s) < 262145) s += s;
		s = substr(s, 0, 262145);
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ body: s }).client.get(URL, {}));
	});

	it('returns HTTP_REQUEST_FAILED for non-string data chunk from uclient', () => {
		assert.match(contains({ ok: false, error: 'HTTP_REQUEST_FAILED' }),
			make_suite({ invalid_data: true }).client.get(URL, {}));
	});
});

// ─── CA file discovery ────────────────────────────────────────────────────────

describe('components.http_client: CA file discovery', () => {
	function ca_files_for(lsdir, access) {
		let s = make_suite({ fs_lsdir: lsdir, fs_access: access });
		s.client.get(URL, {});
		return s.ssl_opts().ca_files;
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
		// /etc/ssl/certs/ca-certificates.crt is a well-known path; if lsdir also returns it
		// the map must not add it twice.
		let files = ca_files_for(
			() => ['ca-certificates.crt'],
			(path) => path === '/etc/ssl/certs/ca-certificates.crt'
		);
		let count = 0;
		for (let f in files) if (f === '/etc/ssl/certs/ca-certificates.crt') count++;
		assert.match(1, count);
	});
});
