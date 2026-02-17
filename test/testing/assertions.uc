import * as printer from 'testing.colors';

export const ASSERT_PREFIX = "__ASSERT__:";

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

function fail(msg, expected, actual) {
    let err = `${ASSERT_PREFIX}${msg || "Assertion failed"}`;
    if (expected != null || actual != null) {
        err += `
      ${printer.color(printer.COLORS.RED, "Expected:")} ${sprintf("%J", expected)}
      ${printer.color(printer.COLORS.RED, "Actual:  ")} ${sprintf("%J", actual)}`;
    }
    die(err);
}

export function assert_eq(actual, expected, msg) {
    if (!deep_equal(actual, expected)) {
        fail(msg || "Equality failed", expected, actual);
    }
};

export function assert(cond, msg) {
    if (!cond) {
        fail(msg);
    }
};

export function assert_throws(fn, msg) {
    let threw = false;
    try { fn(); } catch (e) { threw = true; }
    if (!threw) fail(msg || "Expected function to throw exception");
};

export function assert_match(actual, regex, msg) {
    if (!match(actual, regex)) {
        fail(msg || "Regex match failed", sprintf("%s", regex), actual);
    }
};

export function assert_fail(msg) {
    fail(msg || "Test failed intentionally");
};
