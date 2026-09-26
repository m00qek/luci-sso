'use strict';

/**
 * HTTPS-only HTTP client component backed by uclient and uloop.
 *
 * Enforces TLS on every request (`HTTPS_REQUIRED` for plain-HTTP URLs),
 * verifies server certificates against the system CA bundle, and caps
 * response bodies at 256 KB.
 *
 * @module luci_sso_components_http_client
 * @typedef {{get: (url: string, opts: *) => Result, post: (url: string, opts: *) => Result}} HttpClient
 */

import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { SSL_INIT_FAILED, HTTPS_REQUIRED, HTTP_REQUEST_FAILED } from 'luci_sso.errors';

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

/**
 * Readable names for the codes uclient passes to the error callback. The
 * ucode binding exports no constants, so these were established by
 * triggering each failure against a real uclient in the devenv, and match
 * enum uclient_error_code in upstream uclient.h:
 *   1 UCLIENT_ERROR_CONNECT           connection refused
 *   2 UCLIENT_ERROR_TIMEDOUT          no answer within the timeout
 *   3 UCLIENT_ERROR_SSL_INVALID_CERT  certificate chain not trusted
 *   4 UCLIENT_ERROR_SSL_CN_MISMATCH   certificate does not cover the host
 * Codes never observed (0 UNKNOWN, 5 MISSING_SSL_CONTEXT) keep their number.
 * @private
 */
const UCLIENT_ERRORS = {
	"1": "CONNECTION_FAILED",
	"2": "TIMED_OUT",
	"3": "CERT_UNTRUSTED",
	"4": "CERT_NAME_MISMATCH"
};

function uclient_error_name(code) {
	return UCLIENT_ERRORS["" + code] || `UCLIENT_ERROR_${code}`;
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
		error: function(u, code) { error = uclient_error_name(code); uloop.end(); }
	};

	con = uclient.new(url, null, callbacks);
	if (!con) return Result.err("UCLIENT_ALLOC_FAILED");

	if (!con.ssl_init({ ca_files: get_system_ca_files(fs), verify: true }))
		return Result.err(SSL_INIT_FAILED);

	if (opts.timeout) con.set_timeout(opts.timeout);

	// connect() fails synchronously, before any callback, when the host name
	// does not resolve or there is no route to it (observed in the devenv).
	if (!con.connect()) return Result.err("CONNECT_NOT_STARTED");

	let req_opts = { headers: opts.headers || {} };
	if (opts.post_data) req_opts.post_data = opts.post_data;

	if (!con.request(method, req_opts)) return Result.err("REQUEST_START_FAILED");

	uloop.run();
	con.disconnect();

	if (error) return Result.err(error);
	return Result.ok({ status: response.status, body: response.body });
}

/**
 * Creates an HttpClient.
 *
 * @param {*} uclient uclient C library handle used to open TLS connections.
 * @param {module:uloop} uloop uloop module (or utest proxy) that drives the I/O event loop.
 * @param {module:fs} fs fs module (or utest proxy) used to discover system CA certificates.
 * @returns {HttpClient}
 */
export function create(uclient, uloop, fs) {
	return {
		get: function(url, opts) {
			if (!encoding.is_https(url)) return Result.err(HTTPS_REQUIRED);
			let res = do_request(uclient, uloop, fs, 'GET', url, {
				timeout: 10000,
				headers: (opts && opts.headers) ? opts.headers : {}
			});
			if (!res.ok) return Result.err(HTTP_REQUEST_FAILED, res.error);
			return Result.ok({ status: res.data.status, body: res.data.body });
		},

		post: function(url, opts) {
			if (!encoding.is_https(url)) return Result.err(HTTPS_REQUIRED);
			let res = do_request(uclient, uloop, fs, 'POST', url, {
				timeout: 10000,
				headers: (opts && opts.headers) ? opts.headers : {},
				post_data: (opts && opts.body) ? opts.body : null
			});
			if (!res.ok) return Result.err(HTTP_REQUEST_FAILED, res.error);
			return Result.ok({ status: res.data.status, body: res.data.body });
		}
	};
};
