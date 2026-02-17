import * as assertions from 'testing.assertions';
import * as runner from 'testing.runner';
import * as loader from 'testing.loader';

global.testing_state = global.testing_state || { tests: [] };

// --- DSL Exports ---

export const assert = assertions.assert;
export const assert_eq = assertions.assert_eq;
export const assert_throws = assertions.assert_throws;
export const assert_match = assertions.assert_match;
export const assert_fail = assertions.assert_fail;

/**
 * Registers a standard test.
 */
export function test(name, fn) {
    let mod = loader.normalize_module_name(sourcepath(1), global.testing_state.prefix);

    push(global.testing_state.tests, { 
		name, 
		fn,
        module: mod
	});
};

/**
 * Registers a test that will be skipped.
 */
export function test_skip(name, fn) {
    let mod = loader.normalize_module_name(sourcepath(1), global.testing_state.prefix);

    push(global.testing_state.tests, {
        name,
        fn,
        skipped: true,
        module: mod
    });
};

// --- Internal Lifecycle ---

function clear_tests() {
	global.testing_state.tests = [];
};

// --- Main Entry Point ---

/**
 * Executes multiple test suites based on the provided configuration.
 * 
 * @param {array} suites - Array of {dir, name} objects.
 * @param {object} options - Execution options (verbose, filter, modules, prefix).
 * @returns {boolean} - True if all tests passed.
 */
export function run(suites, options) {
    options = options || {};
    let overall_success = true;

    // 1. Setup Global Context for test registration
    global.testing_state.prefix = options.prefix;

    // 2. Normalize Module Whitelist if present
    if (type(options.modules) == "array") {
        let normalized = [];
        for (let m in options.modules) {
            if (length(m) > 0) {
                push(normalized, loader.normalize_module_name(m, options.prefix));
            }
        }
        options.modules = (length(normalized) > 0) ? normalized : null;
    }

    // 3. Normalize Filter Regex once
    if (type(options.filter) == "string" && length(options.filter) > 0) {
        options.filter = regexp(options.filter);
    } else if (type(options.filter) != "regexp") {
        options.filter = null;
    }

    // 4. Execution Loop
    for (let s in suites) {
        clear_tests();
        loader.load_suite(s.dir, options.prefix, (file, err) => {
            // Register a placeholder test that will fail with the syntax error
            test(`Syntax Error: ${file}`, () => {
                die(err);
            });
        });
        
        if (!runner.run_suite(global.testing_state.tests, s.name, options)) {
            overall_success = false;
        }
    }

    return overall_success;
};
