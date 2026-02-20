'use strict';

import * as uclient from 'uclient';
import * as uloop from 'uloop';
import * as fs from 'fs';

/**
 * Loads system CA certificates from standard OpenWrt locations.
 * This is the ONLY source of trust for the project.
 * @private
 */
function get_system_ca_files() {
    let cas_map = {};
    
    // 1. Check for individual hashed certs (standard OpenWrt /etc/ssl/certs)
    let files = fs.lsdir("/etc/ssl/certs");
    if (files) {
        for (let f in files) {
            // Include both .crt and .pem files commonly found in trust stores
            if (match(f, /\.(crt|pem)$/)) {
                let path = "/etc/ssl/certs/" + f;
                cas_map[path] = true;
            }
        }
    }

    // 2. Check for common bundle files (Audit W5: Deduplicate with directory scan)
    let bundles = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/ssl/ca-bundle.crt"
    ];

    for (let b in bundles) {
        if (!cas_map[b] && fs.access(b)) {
            cas_map[b] = true;
        }
    }

    return keys(cas_map);
}

const MAX_RESPONSE_SIZE = 262144; // 256 KB

/**
 * Performs a synchronous-looking HTTPS request using ONLY system-trusted CAs.
 * 
 * @param {string} method - HTTP method (GET, POST, etc.)
 * @param {string} url - Target URL
 * @param {object} [opts] - { headers, post_data, timeout }
 * @returns {object} - { status, body, error, headers }
 */
export function request(method, url, opts) {
    opts = opts || {};
    uloop.init();

    let response = {
        status: 0,
        body: "",
        error: null,
        headers: {}
    };

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
                if (!data || length(data) == 0) break;
                
                // MANDATORY: Validate data type before concatenation (B4)
                if (type(data) != "string") {
                    response.error = "INVALID_DATA_TYPE";
                    uloop.end();
                    return;
                }

                if ((length(response.body) + length(data)) > MAX_RESPONSE_SIZE) {
                    response.error = "RESPONSE_TOO_LARGE";
                    uloop.end();
                    return;
                }
                response.body += data;
            }
        },
        data_eof: function() {
            uloop.end();
        },
        error: function(u, code) {
            response.error = "UCLIENT_ERROR_" + code;
            uloop.end();
        }
    };

    con = uclient.new(url, null, callbacks);
    if (!con) return { status: 0, body: "", error: "CONNECTION_FAILED" };

    // Set up SSL context using ONLY system CAs
    let ca_files = get_system_ca_files();
    
    // Strict Verification is MANDATORY
    if (!con.ssl_init({ ca_files: ca_files, verify: true })) {
        return { status: 0, body: "", error: "SSL_INIT_FAILED" };
    }

    if (opts.timeout) con.set_timeout(opts.timeout);

    if (!con.connect()) {
        return { status: 0, body: "", error: "CONNECT_FAILED" };
    }

    let req_opts = {
        headers: opts.headers || {}
    };
    if (opts.post_data) req_opts.post_data = opts.post_data;

    if (!con.request(method, req_opts)) {
        return { status: 0, body: "", error: "REQUEST_START_FAILED" };
    }

    uloop.run();
    con.disconnect();

    return response;
};
