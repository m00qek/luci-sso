import * as testing from 'testing';

/**
 * Defines a major action or trigger in the specification.
 */
export function when(desc, fn) {
	testing.test("When " + desc, null, "header", 0);
	fn();
};

/**
 * Defines a specific condition or context.
 */
export function and(desc, fn) {
	testing.test("and " + desc, null, "header", 1);
	fn();
};

/**
 * Defines an assertion that must hold true.
 */
export function then(desc, fn) {
	testing.test("then " + desc, fn, "test", 2);
};
