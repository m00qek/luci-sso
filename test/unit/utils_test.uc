import { test, assert, assert_eq } from 'testing';
import { parse_params, parse_cookies } from 'luci_sso.utils';

test('Utils: Params - URL decoding in query strings', () => {
	let res = parse_params("redirect_uri=http%3A%2F%2Floc%2F&state=abc+123&empty=");
	assert_eq(res.redirect_uri, "http://loc/", "Should decode colon and slash");
	assert_eq(res.state, "abc 123", "Should decode plus as space");
	assert_eq(res.empty, "", "Should handle empty value");
});

test('Utils: Cookies - Robust parsing', () => {
	let str = 'luci_sso_state="eyJhbGc.abc"; Path=/; luci_sso_session=token123';
	let res = parse_cookies(str);
	
	assert_eq(res.luci_sso_state, "eyJhbGc.abc", "Should strip double quotes");
	assert_eq(res.Path, "/", "Should handle spaces after semicolon");
	assert_eq(res.luci_sso_session, "token123", "Should parse multiple cookies");
});

test('Utils: Cookies - Edge cases', () => {
	assert_eq(parse_cookies('a=1;b=2').b, "2");
	assert_eq(parse_cookies('  key  =  val  ').key, "val", "Should trim keys and values");
	assert_eq(parse_cookies('quoted=""').quoted, "", "Should handle empty quotes");
});

test('Utils: Params - Enforce total length limit (16 KB)', () => {
	let massive = "";
	for (let i = 0; i < 2000; i++) massive += "key=value&";
	
	let res = parse_params(massive);
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