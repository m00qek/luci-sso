'use strict';

/**
 * Standardized Result object for luci-sso.
 * Provides a unified way to handle success and failure branches.
 */

const ResultMethods = {};

/**
 * Checks if an object is a valid Result instance.
 */
export function is(obj) {
	return type(obj) == "object" && proto(obj) == ResultMethods;
};

/**
 * Creates a successful Result.
 */
export function ok(data) {
	return proto({ ok: true, data: data }, ResultMethods);
};

/**
 * Creates a failed Result.
 * @param {string} error - Error code
 * @param {any} [details] - Optional error details or context object
 */
export function err(error, details) {
	return proto({ ok: false, error: error, details: details }, ResultMethods);
};
