import { test, assert, assert_eq } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('encoding: url - normalize_url removes trailing slashes', () => {
	assert_eq(encoding.normalize_url("https://idp.com/").data, "https://idp.com");
	assert_eq(encoding.normalize_url("https://idp.com///").data, "https://idp.com");
});

test('encoding: url - normalize_url case normalization', () => {
	assert_eq(encoding.normalize_url("HTTPS://IDP.COM").data, "https://idp.com");
});

test('encoding: url - normalize_url preservation of path', () => {
	assert_eq(encoding.normalize_url("https://idp.com/auth/").data, "https://idp.com/auth");
});

test('encoding: url - normalize_url handles non-string safely', () => {
    try {
        encoding.normalize_url(null);
        assert(false, "Should have thrown for non-string");
    } catch (e) {
        assert(index(e, "CONTRACT_VIOLATION") >= 0, "Should contain CONTRACT_VIOLATION in error");
        assert(index(e, "normalize_url expects string") >= 0, "Should contain reason in error");
    }
});
