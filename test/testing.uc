import * as math from 'math';

global.testing_state = global.testing_state || { tests: [], results: [] };

const ASSERT_PREFIX = "__ASSERT__:";
const C_RESET = "\u001b[0m", 
      C_RED = "\u001b[31m", 
      C_BRED = "\u001b[91m", 
      C_GREEN = "\u001b[32m", 
      C_BOLD = "\u001b[1m", 
      C_YELLOW = "\u001b[33m",
      C_CYAN = "\u001b[36m";

const color = (c, t) => `${c}${t}${C_RESET}`;

function deep_equal(a, b) {
    if (a == b) return true;
    if (type(a) != type(b)) return false;
    if (type(a) == "object") {
        if (length(a) != length(b)) return false;
        for (let k, v in a) {
            if (!deep_equal(v, b[k])) return false;
        }
        return true;
    }
    if (type(a) == "array") {
        if (length(a) != length(b)) return false;
        for (let i = 0; i < length(a); i++) {
            if (!deep_equal(a[i], b[i])) return false;
        }
        return true;
    }
    return false;
}

export function assert_eq(actual, expected, msg) {
    if (!deep_equal(actual, expected)) {
        die(`${ASSERT_PREFIX}${msg || "Equality failed"}\n      ${color(C_RED, "Expected:")} ${expected}\n      ${color(C_RED, "Actual:  ")} ${actual}`);
    }
};

export function assert(cond, msg) {
    if (!cond) {
        die(`${ASSERT_PREFIX}${msg || "Assertion failed"}`);
    }
};

export function assert_throws(fn, msg) {
    let threw = false;
    try { fn(); } catch (e) { threw = true; }
    if (!threw) die(`${ASSERT_PREFIX}${msg || "Expected function to throw exception"}`);
};

export function test(name, fn, type, depth) {
    push(global.testing_state.tests, { 
		name, 
		fn, 
		type: type || "test", 
		depth: depth || 0 
	});
};

export function clear_tests() {
	global.testing_state.tests = [];
};

/**
 * Colors the keywords in a specification string.
 */
function colorize_spec(str) {
	let res = str;
	res = replace(res, /^When /, color(C_CYAN, "When "));
	res = replace(res, /^and /, color(C_YELLOW, "and "));
	res = replace(res, /^then /, color(C_YELLOW, "then "));
	return res;
}

/**
 * Executes a single test item and returns a result object.
 */
function run_item(t) {
	if (!t.fn) return { ok: true, type: "header" };
	try {
		t.fn();
		return { ok: true, type: "test" };
	} catch (e) {
		let err_str = sprintf("%s", e);
		let is_assertion = (index(err_str, ASSERT_PREFIX) == 0);
		if (is_assertion) {
			return { ok: false, type: "test", failure: replace(err_str, ASSERT_PREFIX, "") };
		} else {
			return { ok: false, type: "test", error: (type(e) == "object" && e.stack) ? e.stack : err_str };
		}
	}
}

export function run_all(suite_name) {
    let tests = global.testing_state.tests;
    let start_time = clock();
    let verbose = (getenv("VERBOSE") == "1");
    let passed = 0;
    let failed = 0;
    let errors = 0;
    let failures_list = [];
    let errors_list = [];

    if (suite_name) {
        print(`\n${color(C_BOLD + C_CYAN, "● Suite: " + suite_name)}\n\n`);
    }

    for (let i = 0; i < length(tests); ) {
		let t = tests[i];

		// Case 1: Start of a specification (When block)
		if (t.type == "header" && t.depth == 0 && index(t.name, "When ") == 0) {
			let spec_results = [];
			let all_ok = true;
			let j = i + 1;

			while (j < length(tests) && tests[j].depth > 0) {
				let child = tests[j];
				if (all_ok) {
					let res = run_item(child);
					push(spec_results, { item: child, result: res });
					if (!res.ok) {
						all_ok = false;
						if (res.failure) failed++; else errors++;
						push(res.failure ? failures_list : errors_list, { name: child.name, error: res.failure || res.error });
					} else if (res.type == "test") {
						passed++;
					}
				} else {
					// Skip remaining items in the when block
					push(spec_results, { item: child, result: { ok: true, type: "skipped" } });
				}
				j++;
			}

			if (verbose) {
				let status = all_ok ? color(C_GREEN, "[PASS]") : color(C_RED, "[FAIL]");
				print(`${status} ${color(C_BOLD, colorize_spec(t.name))}\n`);
				for (let r in spec_results) {
					let indent = "";
					for (let k = 0; k < r.item.depth; k++) indent += "  ";
					
					if (r.result.type == "header") {
						print(`${indent}${color(C_BOLD, colorize_spec(r.item.name))}\n`);
					} else if (r.result.type == "skipped") {
						// Don't print skipped tests to keep it clean, or print in gray
						// print(`${indent}${color("\u001b[90m", "[SKIP]")} ${colorize_spec(r.item.name)}\n`);
					} else {
						let s = r.result.ok ? color(C_GREEN, "[PASS]") : color(C_RED, "[FAIL]");
						print(`${indent}${s} ${colorize_spec(r.item.name)}\n`);
						if (!r.result.ok) {
							let msg = r.result.failure || r.result.error;
							print(`${indent}       ${replace(msg, /\n/g, "\n" + indent + "       ")}\n\n`);
						}
					}
				}
				print("\n");
			} else {
				print(all_ok ? color(C_GREEN, "●") : color(C_RED, "■"));
			}
			i = j;
			continue;
		}

		// Case 2: Standard Unit Test
		let res = run_item(t);
		if (res.ok) {
			passed++;
			if (verbose) {
				print(`${color(C_GREEN, "[PASS]")} ${colorize_spec(t.name)}\n`);
			} else {
				print(color(C_GREEN, "●"));
			}
		} else {
			if (res.failure) failed++; else errors++;
			push(res.failure ? failures_list : errors_list, { name: t.name, error: res.failure || res.error });
			if (verbose) {
				print(`${color(C_RED, "[FAIL]")} ${colorize_spec(t.name)}\n       ${res.failure || res.error}\n\n`);
			} else {
				print(color(C_RED, "■"));
			}
		}
		i++;
    }

    if (!verbose) print("\n");

    let end_time = clock();
    let duration = (end_time[0] - start_time[0]) + ((end_time[1] - start_time[1]) / 1000000000.0);

    print(`${color(C_GREEN, passed)} successes / ` +
          `${color(C_RED, failed)} failures / ` +
          `${color(C_BRED, errors)} errors ` +
          `(${color(C_BOLD, sprintf("%.6f", duration))} seconds)\n`);

    if (failed > 0 || errors > 0) {
        exit(1);
    }
};
