import * as crypto from 'luci_sso.crypto';

/**
 * Generates a signed HS256 ID Token for Tier 2 business logic testing.
 * 
 * @param {object} payload - Claims to include in the token.
 * @param {string} secret - Symmetric secret for signing.
 * @returns {string} - Compact JWS string.
 */
export function generate_id_token(payload, secret) {
    return crypto.sign_jws(payload, secret);
};

/**
 * Creates a mock IO provider for Tier 2 tests.
 */
export function create_mock_io(now) {
    let io = {};
    io._now = now || 1000000;
    io._files = {};
    io._responses = {};
    
    io.time = function() { return io._now; };
    
    io.read_file = function(path) { 
        if (io._files[path] == null) return null;
        return io._files[path]; 
    };
    
    io.write_file = function(path, data) { 
        io._files[path] = data; 
        return true; 
    };
    
    io.rename = function(old, newpath) {
        if (io._files[old] == null) die("NOENT");
        io._files[newpath] = io._files[old];
        delete io._files[old];
        return true;
    };

    io.remove = function(path) {
        delete io._files[path];
        return true;
    };

    io.mkdir = function(path, mode) {
        return true;
    };

    io.lsdir = function(path) {
        let results = [];
        let prefix = path;
        if (substr(prefix, -1) != "/") prefix += "/";
        for (let f in io._files) {
            if (index(f, prefix) == 0) {
                push(results, substr(f, length(prefix)));
            }
        }
        return results;
    };

    io.stat = function(path) {
        if (io._files[path] == null) return null;
        return { mtime: io._now }; // Simpler: use io._now as mtime
    };
    
    io.http_get = function(url) {
        let res = io._responses[url] || { status: 404, body: "" };
        let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
        return { status: res.status, body: { read: () => raw_body } };
    };
    
    io.http_post = function(url, opts) {
        let res = io._responses[url] || { status: 404, body: "" };
        let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
        return { status: res.status, body: { read: () => raw_body } };
    };
    
    io.log = function() { /* quiet by default */ };
    
    return io;
};
