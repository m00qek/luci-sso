import { constant_time_eq } from 'luci_sso.crypto';
import { describe, it, assert, truthy, falsy } from 'utest';

describe('crypto: constant_time_eq', () => {
	it('identical strings', () => {
		assert.match(truthy(), constant_time_eq('hello', 'hello'), 'Should return true for identical strings');
	});

	it('different strings of same length', () => {
		assert.match(falsy(), constant_time_eq('hello', 'world'), 'Should return false for different strings of same length');
	});

	it('different strings of different length', () => {
		assert.match(falsy(), constant_time_eq('hello', 'helloo'), 'Should return false for different lengths');
	});

	it('empty strings', () => {
		assert.match(truthy(), constant_time_eq('', ''), 'Should return true for empty strings');
	});

	it('single byte difference', () => {
		assert.match(falsy(), constant_time_eq('abcde', 'abfde'), 'Should return false for single byte difference');
	});

	it('null/undefined/non-string inputs', () => {
		assert.match(falsy(), constant_time_eq(null, 'test'), 'Should return false for null first arg');
		assert.match(falsy(), constant_time_eq('test', null), 'Should return false for null second arg');
		assert.match(falsy(), constant_time_eq(undefined, undefined), 'Should return false for undefined');
		assert.match(falsy(), constant_time_eq(123, '123'), 'Should return false for number');
		assert.match(falsy(), constant_time_eq({foo: 'bar'}, 'baz'), 'Should return false for object');
	});

	it('binary strings', () => {
		let a = '\x00\x01\x02\xFF';
		let b = '\x00\x01\x02\xFF';
		let c = '\x00\x01\x02\xFE';
		assert.match(truthy(), constant_time_eq(a, b), 'Should return true for identical binary strings');
		assert.match(falsy(), constant_time_eq(a, c), 'Should return false for differing binary strings');
	});

	it('multi-value / array inputs', () => {
		let trusted = "correct_state_123";
		let untrusted_array = ["correct_state_123", "malicious_injection"];
		assert.match(falsy(), constant_time_eq(untrusted_array, trusted), 'Should return false when input is an array (fail-closed)');
	});

	it('very long strings', () => {
		let long_a = "1234567890ABCDEF1234567890ABCDEF"; // 32 bytes
		for (let i = 0; i < 9; i++) long_a += long_a; // 32 * 2^9 = 16,384 (16KB)

		let long_b = long_a;
		let long_c = long_a + "X";
		let long_d = substr(long_a, 0, length(long_a) - 1) + "X";

		assert.match(truthy(), constant_time_eq(long_a, long_b), 'Should handle long identical strings');
		assert.match(falsy(), constant_time_eq(long_a, long_c), 'Should handle different lengths (long)');
		assert.match(falsy(), constant_time_eq(long_a, long_d), 'Should handle long strings with single byte diff at end');
	});

	it('length leakage prevention logic', () => {
		assert.match(falsy(), constant_time_eq('abc', 'abcd'), 'Should return false for prefix match with different length');
		assert.match(falsy(), constant_time_eq('abcd', 'abc'), 'Should return false for suffix match with different length');
		assert.match(falsy(), constant_time_eq('a', 'b'), 'Should return false for different single bytes');
	});

	it('max_len logic verification', () => {
		let long = "this_is_a_very_long_string_to_test_max_len_logic_123456789";
		let short = "this_is_a_very_long_string";
		assert.match(falsy(), constant_time_eq(short, long), 'Should return false for prefix (short, long)');
		assert.match(falsy(), constant_time_eq(long, short), 'Should return false for prefix (long, short)');
	});
});
