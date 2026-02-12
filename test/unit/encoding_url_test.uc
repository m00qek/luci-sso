import { test, assert, assert_eq } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('encoding: url - normalize_url removes trailing slashes', () => {
	assert_eq(encoding.normalize_url("https://idp.com/"), "https://idp.com");
	assert_eq(encoding.normalize_url("https://idp.com///"), "https://idp.com");
});

test('encoding: url - normalize_url case normalization', () => {
	assert_eq(encoding.normalize_url("HTTPS://IDP.COM"), "https://idp.com");
});

test('encoding: url - normalize_url preservation of path', () => {
	assert_eq(encoding.normalize_url("https://idp.com/auth/"), "https://idp.com/auth");
});

test('encoding: url - normalize_url handles non-string safely', () => {
	assert_eq(encoding.normalize_url(null), "");
});
