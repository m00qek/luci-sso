'use strict';

import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { SSL_INIT_FAILED } from 'luci_sso.errors';

const LIMIT_RESPONSE_SIZE = 262144; // 256 KB

function get_system_ca_files(fs) {
	let cas_map = {};

	let files = fs.lsdir("/etc/ssl/certs");
	if (files) {
		for (let f in files) {
			if (match(f, /\.(crt|pem)$/))
				cas_map["/etc/ssl/certs/" + f] = true;
		}
	}

	for (let b in ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/ssl/ca-bundle.crt"]) {
		if (!cas_map[b] && fs.access(b))
			cas_map[b] = true;
	}

	return keys(cas_map);
}

function do_request(uclient, uloop, fs, method, url, opts) {
	uloop.init();

	let response = { status: 0, body: "", headers: {} };
	let error = null;
	let con;

	let callbacks = {
		header_done: function() {
			response.headers = con.get_headers();
			response.status = con.status().status;
		},
		data_read: function() {
			let data;
			while (true) {
				data = con.read();
				if (!data || length(data) === 0) break;
				if (type(data) !== "string") {
					error = "INVALID_DATA_TYPE";
					uloop.end();
					return;
				}
				if (length(response.body) + length(data) > LIMIT_RESPONSE_SIZE) {
					error = "RESPONSE_TOO_LARGE";
					uloop.end();
					return;
				}
				response.body += data;
			}
		},
		data_eof:  function() { uloop.end(); },
		error: function(u, code) { error = "UCLIENT_ERROR_" + code; uloop.end(); }
	};

	con = uclient.new(url, null, callbacks);
	if (!con) return Result.err("UCLIENT_ALLOC_FAILED");

	if (!con.ssl_init({ ca_files: get_system_ca_files(fs), verify: true }))
		return Result.err(SSL_INIT_FAILED);

	if (opts.timeout) con.set_timeout(opts.timeout);

	if (!con.connect()) return Result.err("TLS_CONNECT_FAILED");

	let req_opts = { headers: opts.headers || {} };
	if (opts.post_data) req_opts.post_data = opts.post_data;

	if (!con.request(method, req_opts)) return Result.err("REQUEST_START_FAILED");

	uloop.run();
	con.disconnect();

	if (error) return Result.err(error);
	return Result.ok({ status: response.status, body: response.body });
}

/**
 * Creates an HTTPS-only HTTP client.
 *
 * @param {object} uclient - The uclient module (or a utest proxy of it)
 * @param {object} uloop   - The uloop module (or a utest proxy of it)
 * @param {object} fs      - The fs module (or a utest proxy of it)
 * @returns {{ get, post }}
 */
export function create(uclient, uloop, fs) {
	return {
		get: function(url, opts) {
			if (!encoding.is_https(url)) return Result.err("HTTPS_REQUIRED");
			let res = do_request(uclient, uloop, fs, 'GET', url, {
				timeout: 10000,
				headers: (opts && opts.headers) ? opts.headers : {}
			});
			if (!res.ok) return Result.err("HTTP_REQUEST_FAILED", res.error);
			return Result.ok({ status: res.data.status, body: res.data.body });
		},

		post: function(url, opts) {
			if (!encoding.is_https(url)) return Result.err("HTTPS_REQUIRED");
			let res = do_request(uclient, uloop, fs, 'POST', url, {
				timeout: 10000,
				headers: (opts && opts.headers) ? opts.headers : {},
				post_data: (opts && opts.body) ? opts.body : null
			});
			if (!res.ok) return Result.err("HTTP_REQUEST_FAILED", res.error);
			return Result.ok({ status: res.data.status, body: res.data.body });
		}
	};
}
