import { test, assert, assert_eq } from 'testing';
import { parse_params } from 'luci_sso.utils';

test('Utils: Params - Parse standard query string', () => {
	let res = parse_params("a=1&b=2");
	assert_eq(res.a, "1");
	assert_eq(res.b, "2");
});

test('Utils: Params - Parse cookie string with semicolon', () => {
	let res = parse_params("sess=123; state=abc", ";");
	assert_eq(res.sess, "123");
	assert_eq(res.state, "abc");
});

test('Utils: Params - Enforce total length limit (16 KB)', () => {
	let massive = "";
	for (let i = 0; i < 2000; i++) massive += "key=value&";
	
	let res = parse_params(massive);
	// Length is ~20,000, should return empty object
	assert_eq(length(res), 0, "Should return empty object if string is too large");
});

test('Utils: Params - Enforce parameter count limit (100)', () => {
	let many = "";
	for (let i = 0; i < 150; i++) many += `k${i}=v&`;
	
	let res = parse_params(many);
	assert_eq(length(res), 100, "Should stop parsing after 100 parameters");
});

test('Utils: Params - Handle empty or invalid inputs', () => {
	assert_eq(length(parse_params(null)), 0);
	assert_eq(length(parse_params("")), 0);
	assert_eq(length(parse_params(123)), 0);
});
