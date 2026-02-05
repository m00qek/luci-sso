import * as math from 'math';

global.testing_state = global.testing_state || { tests: [], results: [] };
let tests = global.testing_state.tests;

const ASSERT_PREFIX = "__ASSERT__:";
const C_RESET = "\u001b[0m", 
      C_RED = "\u001b[31m", 
      C_BRED = "\u001b[91m", 
      C_GREEN = "\u001b[32m", 
      C_BOLD = "\u001b[1m", 
      C_YELLOW = "\u001b[33m";

const color = (c, t) => `${c}${t}${C_RESET}`;

function shuffle(arr) {
    math.srand(clock()[1]);
    for (let i = length(arr) - 1; i > 0; i--) {
        let j = math.rand() % (i + 1);
        let tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

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

export function test(name, fn) {
    push(tests, { name, fn });
};

export function run_all() {
    let start_time = clock();
    let verbose = (getenv("VERBOSE") == "1");
    let passed = 0;
    let failed = 0;
    let errors = 0;
    let failures_list = [];
    let errors_list = [];

    // Randomize test order
    shuffle(tests);

    if (verbose) {
        print(`\n${color(C_BOLD, "Running Tests...")}\n${color(C_GREEN, "----------------")}\n`);
    }

    for (let t in tests) {
        try {
            t.fn();
            passed++;
            if (verbose) {
                print(`${color(C_GREEN, "[PASS]")} ${t.name}\n`);
            } else {
                print(color(C_GREEN, "●"));
            }
        } catch (e) {
            let err_str = sprintf("%s", e);
            let is_assertion = (index(err_str, ASSERT_PREFIX) == 0);
            
            if (is_assertion) {
                let clean_msg = replace(err_str, ASSERT_PREFIX, "");
                clean_msg = replace(clean_msg, /\n$/, "");
                failed++;
                push(failures_list, { name: t.name, error: clean_msg });
                if (verbose) {
                    print(`${color(C_RED, "[FAIL]")} ${t.name}\n       ${clean_msg}\n\n`);
                } else {
                    print(color(C_RED, "■"));
                }
            } else {
                errors++;
                let error_msg = (type(e) == "object" && e.stack) ? e.stack : err_str;
                push(errors_list, { name: t.name, error: error_msg });
                if (verbose) {
                    print(`${color(C_BRED, "[ERR ]")} ${t.name}\n       ${error_msg}\n\n`);
                } else {
                    print(color(C_BRED, "✗"));
                }
            }
        }
    }

    if (!verbose) print("\n");

    let end_time = clock();
    let duration = (end_time[0] - start_time[0]) + ((end_time[1] - start_time[1]) / 1000000000.0);

    let s_color = (passed > 0) ? C_GREEN : C_RESET;
    let p_color = C_YELLOW;

    if (verbose) print(color(C_GREEN, "----------------") + "\n");
    
    print(`${color(s_color, passed)} successes / ` +
          `${color(C_RED, failed)} failures / ` +
          `${color(C_BRED, errors)} errors / ` +
          `${color(p_color, 0)} pending : ` +
          `${color(C_BOLD, sprintf("%.6f", duration))} seconds\n`);

    if (length(failures_list) > 0) {
        print(`\n${color(C_BOLD, "Failures:")}\n`);
        for (let f in failures_list) {
            print(`${color(C_RED, "Failure")} → ${f.name}\n${f.error}\n\n`);
        }
    }

    if (length(errors_list) > 0) {
        print(`\n${color(C_BOLD, "Errors:")}\n`);
        for (let e in errors_list) {
            print(`${color(C_BRED, "Error")} → ${e.name}\n${e.error}\n\n`);
        }
    }
    
    if (failed > 0 || errors > 0) {
        exit(1);
    }
};