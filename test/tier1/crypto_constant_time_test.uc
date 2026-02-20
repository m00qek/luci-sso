import { constant_time_eq } from 'luci_sso.crypto';
import { assert, test } from 'testing';

test('crypto: constant_time_eq - identical strings', () => {
    assert(constant_time_eq('hello', 'hello'), 'Should return true for identical strings');
});

test('crypto: constant_time_eq - different strings of same length', () => {
    assert(!constant_time_eq('hello', 'world'), 'Should return false for different strings of same length');
});

test('crypto: constant_time_eq - different strings of different length', () => {
    assert(!constant_time_eq('hello', 'helloo'), 'Should return false for different lengths');
});

test('crypto: constant_time_eq - empty strings', () => {
    assert(constant_time_eq('', ''), 'Should return true for empty strings');
});

test('crypto: constant_time_eq - single byte difference', () => {
    assert(!constant_time_eq('abcde', 'abfde'), 'Should return false for single byte difference');
});

test('crypto: constant_time_eq - null/undefined/non-string inputs', () => {
    assert(!constant_time_eq(null, 'test'), 'Should return false for null first arg');
    assert(!constant_time_eq('test', null), 'Should return false for null second arg');
    assert(!constant_time_eq(undefined, undefined), 'Should return false for undefined');
    assert(!constant_time_eq(123, '123'), 'Should return false for number');
    assert(!constant_time_eq({foo: 'bar'}, 'baz'), 'Should return false for object');
});

test('crypto: constant_time_eq - binary strings', () => {
    let a = '\x00\x01\x02\xFF';
    let b = '\x00\x01\x02\xFF';
    let c = '\x00\x01\x02\xFE';
    assert(constant_time_eq(a, b), 'Should return true for identical binary strings');
    assert(!constant_time_eq(a, c), 'Should return false for differing binary strings');
});

test('crypto: constant_time_eq - multi-value / array inputs', () => {
    let trusted = "correct_state_123";
    let untrusted_array = ["correct_state_123", "malicious_injection"];
    assert(!constant_time_eq(untrusted_array, trusted), 'Should return false when input is an array (fail-closed)');
});

test('crypto: constant_time_eq - very long strings', () => {
    // 16KB is sufficient for a "long" string in this context
    let long_a = "1234567890ABCDEF1234567890ABCDEF"; // 32 bytes
    for (let i = 0; i < 9; i++) long_a += long_a; // 32 * 2^9 = 16,384 (16KB)
    
    let long_b = long_a;
    let long_c = long_a + "X";
    let long_d = substr(long_a, 0, length(long_a) - 1) + "X";

    assert(constant_time_eq(long_a, long_b), 'Should handle long identical strings');
    assert(!constant_time_eq(long_a, long_c), 'Should handle different lengths (long)');
    assert(!constant_time_eq(long_a, long_d), 'Should handle long strings with single byte diff at end');
});

test('crypto: constant_time_eq - length leakage prevention logic', () => {
    assert(!constant_time_eq('abc', 'abcd'), 'Should return false for prefix match with different length');
    assert(!constant_time_eq('abcd', 'abc'), 'Should return false for suffix match with different length');
    assert(!constant_time_eq('a', 'b'), 'Should return false for different single bytes');
});

test('crypto: constant_time_eq - max_len logic verification', () => {
    // Specifically test that if we pass a long string as the SECOND argument, 
    // it still fails and processes correctly.
    let long = "this_is_a_very_long_string_to_test_max_len_logic_123456789";
    let short = "this_is_a_very_long_string";
    assert(!constant_time_eq(short, long), 'Should return false for prefix (short, long)');
    assert(!constant_time_eq(long, short), 'Should return false for prefix (long, short)');
});
