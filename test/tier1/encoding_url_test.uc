import { it, assert, truthy, falsy } from 'utest';
import * as encoding from 'luci_sso.encoding';

it('encoding: url - normalize_url removes trailing slashes', () => {
	assert.match("https://idp.com", encoding.normalize_url("https://idp.com/").data);
	assert.match("https://idp.com", encoding.normalize_url("https://idp.com///").data);
});

it('encoding: url - normalize_url case normalization', () => {
	assert.match("https://idp.com", encoding.normalize_url("HTTPS://IDP.COM").data);
});

it('encoding: url - normalize_url preservation of path', () => {
	assert.match("https://idp.com/auth", encoding.normalize_url("https://idp.com/auth/").data);
});

it('encoding: url - normalize_url handles non-string safely', () => {
	let res = encoding.normalize_url(null);
	assert.match(falsy(), res.ok, "Should return Result.err for non-string");
	assert.match(truthy(), index(res.error, "INVALID_ARGUMENT") >= 0, "Should contain INVALID_ARGUMENT in error");
});
