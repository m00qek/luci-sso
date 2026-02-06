import { test, assert, assert_eq } from 'testing';
import { parse_params, parse_cookies } from 'luci_sso.utils';

// =============================================================================
// Tier 2: Utility Logic
// =============================================================================

test('LOGIC: Utils - URL Parameter Decoding', () => {
	let res = parse_params("redirect_uri=http%3A%2F%2Floc%2F&state=abc+123&empty=");
	assert_eq(res.redirect_uri, "http://loc/", "Should decode colon and slash");
	assert_eq(res.state, "abc 123", "Should decode plus as space");
	assert_eq(res.empty, "", "Should handle empty value");
});

test('LOGIC: Utils - Cookie Parsing Robustness', () => {
	let str = 'luci_sso_state="eyJhbGc.abc"; Path=/; luci_sso_session=token123';
	let res = parse_cookies(str);
	
	assert_eq(res.luci_sso_state, "eyJhbGc.abc", "Should strip double quotes");
	assert_eq(res.luci_sso_session, "token123", "Should parse multiple cookies");
	assert_eq(parse_cookies('  key  =  val  ').key, "val", "Should trim keys and values");
});

test('LOGIC: Utils - Enforce Limits', () => {
    // 1. Length Limit (16KB)
	let massive = "";
	for (let i = 0; i < 2000; i++) massive += "key=value&";
	assert_eq(length(parse_params(massive)), 0, "Should reject massive parameter string");

    // 2. Count Limit (100)
	let many = "";
	for (let i = 0; i < 150; i++) many += `k${i}=v&`;
	assert_eq(length(parse_params(many)), 100, "Should limit parameter count to 100");
});

test('LOGIC: Utils - Invalid Inputs', () => {
	assert_eq(length(parse_params(null)), 0);
	assert_eq(length(parse_params(123)), 0);
});
