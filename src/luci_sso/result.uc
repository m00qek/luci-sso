'use strict';

/**
 * Standardised result monad for luci-sso.
 *
 * Every fallible operation returns a `Result`. On success `ok` is `true`
 * and `data` carries the value. On failure `ok` is `false`, `error` holds
 * a short uppercase code (e.g. `"INVALID_SID"`), and `details` may carry
 * additional diagnostic context that is never forwarded to callers.
 *
 * @module luci_sso_result
 * @typedef {{ok: boolean, data: *, error: string, details: *}} Result
 */

const ResultMethods = {};

/**
 * Returns `true` if `obj` was produced by `ok()` or `err()`.
 *
 * @param {*} obj Value to test.
 * @returns {boolean}
 */
export function is(obj) {
	return type(obj) == "object" && proto(obj) == ResultMethods;
};

/**
 * Wraps a successful value in a Result.
 *
 * @param {*} data Success payload; may be `null` for void operations.
 * @returns {Result}
 */
export function ok(data) {
	return proto({ ok: true, data: data }, ResultMethods);
};

/**
 * Formats a failed Result for a log line: the code, plus the details in
 * parentheses when they are a string (a lower-level cause such as
 * "CERT_UNTRUSTED"). Object details, such as { http_status }, are left out.
 *
 * @param {Result} res A failed Result.
 * @returns {string}
 */
export function describe(res) {
	return (type(res.details) == "string" && length(res.details) > 0)
		? `${res.error} (${res.details})`
		: `${res.error}`;
};

/**
 * Wraps a failure in a Result.
 *
 * @param {string} error Short uppercase error code identifying the failure.
 * @param {*} [details] Optional diagnostic context (stack trace, raw error string, etc.).
 * @returns {Result}
 */
export function err(error, details) {
	return proto({ ok: false, error: error, details: details }, ResultMethods);
};
