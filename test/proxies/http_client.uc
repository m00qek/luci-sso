import * as Result from 'luci_sso.result';

/**
 * Creates a mock HTTP client for use in tests.
 *
 * config.data     — URL-keyed responses: { [url]: { status, body } } or { [url]: { error: "X" } }
 *                   body may be a string or an object (auto-serialized to JSON).
 *                   error entries return Result.err("HTTP_REQUEST_FAILED", error) to match
 *                   the shape the real http_client produces.
 * config.behavior — function overrides: { get: (url, opts) => Result, post: (url, opts) => Result }
 * config.strict   — if true, die() on any unmocked URL instead of returning HTTP_NOT_FOUND.
 *
 * Returns: { get, post, __utest__: { calls: { get: [[url, opts], ...], post: [...] } } }
 *
 * Usage:
 *   import * as http_mock from 'proxies.http_client';
 *   let http = http_mock.create({ data: { [url]: { status: 200, body: f.MOCK_DISCOVERY } } });
 *   let deps = { http, log: () => null, fs, clock };
 */
export function create(config) {
	config = config || {};
	let data     = config.data     || {};
	let behavior = config.behavior || {};
	let calls    = { get: [], post: [] };

	let make_response = function(url) {
		let entry = data[url];
		if (entry == null) {
			if (config.strict) die("strict http mock: unmocked URL: " + url);
			return Result.err("HTTP_REQUEST_FAILED", "HTTP_NOT_FOUND");
		}
		if (entry.error)
			return Result.err("HTTP_REQUEST_FAILED", entry.error);
		let body = (type(entry.body) == "object") ? sprintf("%J", entry.body) : (entry.body || "");
		return Result.ok({ status: entry.status || 200, body: body });
	};

	return {
		get: function(url, opts) {
			push(calls.get, [url, opts]);
			if (behavior.get) return behavior.get(url, opts);
			return make_response(url);
		},

		post: function(url, opts) {
			push(calls.post, [url, opts]);
			if (behavior.post) return behavior.post(url, opts);
			return make_response(url);
		},

		__utest__: { calls: calls }
	};
}
