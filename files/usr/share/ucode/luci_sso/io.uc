'use strict';

import * as fs from 'fs';
import * as uci from 'uci';
import * as ubus from 'ubus';
import * as lucihttp from 'lucihttp';
import * as secure_http from 'luci_sso.secure_http';

let _ubus_conn = null;

/**
 * Creates the real production IO provider.
 * 
 * @returns {object} - IO provider implementing the luci-sso contract.
 */
export function create() {
	return {
		time: () => time(),
		read_file: (path) => fs.readfile(path),
		write_file: (path, data) => fs.writefile(path, data),
		rename: (old, newpath) => fs.rename(old, newpath),
		remove: (path) => fs.unlink(path),
		mkdir: (path, mode) => fs.mkdir(path, mode),
		lsdir: (path) => fs.lsdir(path),
		stat: (path) => fs.stat(path),
		
		log: (level, msg) => warn(`[luci-sso] [${level}] ${msg}\n`),

		http_get: function(url) {
			// MANDATORY: HTTPS only (Blocker #6)
			if (substr(url, 0, 8) !== "https://") {
				this.log("error", `Security violation: Blocked insecure HTTP GET to ${url}`);
				return { error: "HTTPS_REQUIRED" };
			}
			let res = secure_http.request('GET', url, { timeout: 10000 });
			if (res.error) {
				this.log("error", `HTTPS GET failed for ${url}: ${res.error}`);
				return { error: "NETWORK_ERROR" };
			}
			return { status: res.status, body: res.body };
		},

		http_post: function(url, opts) {
			// MANDATORY: HTTPS only (Blocker #6)
			if (substr(url, 0, 8) !== "https://") {
				this.log("error", `Security violation: Blocked insecure HTTP POST to ${url}`);
				return { error: "HTTPS_REQUIRED" };
			}
			let headers = (opts && opts.headers) ? opts.headers : {};
			let post_data = (opts && opts.body) ? opts.body : null;
			
			let res = secure_http.request('POST', url, { 
				timeout: 10000, 
				headers: headers,
				post_data: post_data 
			});
			if (res.error) {
				this.log("error", `HTTPS POST failed for ${url}: ${res.error}`);
				return { error: "NETWORK_ERROR" };
			}
			return { status: res.status, body: res.body };
		},

		urlencode: lucihttp.urlencode,
		getenv: getenv,
		
		ubus_call: (obj, method, args) => {
			if (!_ubus_conn) {
				_ubus_conn = ubus.connect();
				if (!_ubus_conn) return null;
			}
			return _ubus_conn.call(obj, method, args);
		},

		uci_cursor: () => uci.cursor(),
		fserror: () => fs.error(),
		stdout: fs.stdout
	};
};
