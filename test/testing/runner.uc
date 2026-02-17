import * as math from 'math';
import * as assertions from 'testing.assertions';
import * as matcher from 'testing.matcher';
import * as compact_reporter from 'testing.compact_reporter';
import * as detailed_reporter from 'testing.detailed_reporter';
import { STATUS } from 'testing.status';

function shuffle(array) {
	let n = length(array);
	for (let i = n - 1; i > 0; i--) {
		let j = math.rand() % (i + 1);
		let temp = array[i];
		array[i] = array[j];
		array[j] = temp;
	}
	return array;
}

function run_test(t, options) {
    if (matcher.should_ignore(t, options)) {
        return { status: STATUS.IGNORE };
    }
    if (t.skipped) {
        return { status: STATUS.SKIP };
    }

    try {
        t.fn();
        return { status: STATUS.PASS };
    } catch (e) {
        let err_str = sprintf("%s", e);
        let prefix = assertions.ASSERT_PREFIX;
        let is_assertion = (index(err_str, prefix) == 0);
        
        if (is_assertion) {
            return { status: STATUS.FAIL, failure: replace(err_str, prefix, "") };
        } else {
            return { status: STATUS.ERROR, error: (type(e) == "object" && e.stack) ? e.stack : err_str };
        }
    }
}

/**
 * Executes a single test suite.
 * Handles pre-filtering, reporter selection, and execution.
 */
export function run_suite(tests, suite_name, options) {
    options = options || {};
    
    // 1. Pre-filter Check: Should we even run this suite?
    let has_match = false;
    let suite_modules_map = {};
    for (let t in tests) {
        if (!matcher.should_ignore(t, options)) {
            has_match = true;
            suite_modules_map[t.module] = true;
        }
    }

    if (!has_match) {
        return true;
    }

    // 2. Prepare Suite Context
    let suite_options = { ...options };
    if (type(options.modules) == "array") {
        suite_options.modules = keys(suite_modules_map);
    }

    let reporter = suite_options.verbose ? detailed_reporter : compact_reporter;
    let start_time = clock();
    
    let stats = {
        passed_count: 0,
        failed_count: 0,
        errors_count: 0,
        skipped_count: 0,
        filtered_count: 0,
        failures: [],
        errors: [],
        skips: []
    };

    reporter.on_suite_start(suite_name, suite_options);

    // 3. Execution
    shuffle(tests);

    for (let i = 0; i < length(tests); i++) {
        let t = tests[i];
        let res = run_test(t, suite_options);
        
        if (res.status == STATUS.IGNORE) {
            stats.filtered_count++;
            continue;
        }

        if (res.status == STATUS.SKIP) {
            stats.skipped_count++;
            push(stats.skips, { name: t.name });
            reporter.on_test_result(t, res);
            continue;
        }

        if (res.status == STATUS.PASS) {
            stats.passed_count++;
        } else if (res.status == STATUS.FAIL) {
            stats.failed_count++;
            push(stats.failures, { name: t.name, error: res.failure });
        } else if (res.status == STATUS.ERROR) {
            stats.errors_count++;
            push(stats.errors, { name: t.name, error: res.error });
        }

        reporter.on_test_result(t, res);
    }

    let end_time = clock();
    stats.duration = (end_time[0] - start_time[0]) + ((end_time[1] - start_time[1]) / 1000000000.0);

    reporter.on_suite_end(stats);

    return (stats.failed_count == 0 && stats.errors_count == 0);
};
