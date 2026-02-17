'use strict';

import { test, assert, assert_eq } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('Encoding: is_https - basic cases', () => {
	assert(encoding.is_https("https://example.com"), "Standard https should pass");
	assert(!encoding.is_https("http://example.com"), "Standard http should fail");
	assert(!encoding.is_https("ftp://example.com"), "FTP should fail");
	assert(!encoding.is_https("https"), "Incomplete URL should fail");
});

test('Encoding: is_https - case insensitivity (B4)', () => {
	assert(encoding.is_https("HTTPS://example.com"), "UPPERCASE HTTPS should pass");
	assert(encoding.is_https("Https://example.com"), "MixedCase Https should pass");
	assert(encoding.is_https("htTps://example.com"), "htTps should pass");
});

test('Encoding: is_https - edge cases', () => {
	assert(!encoding.is_https(null), "null should fail");
	assert(!encoding.is_https(123), "number should fail");
	assert(!encoding.is_https({}), "object should fail");
	assert(!encoding.is_https(""), "empty string should fail");
});
