'use strict';

import { it, assert, truthy } from 'utest';
import * as encoding from 'luci_sso.encoding';

it('Encoding: is_https - basic cases', () => {
	assert.match(truthy(), encoding.is_https("https://example.com"), "Standard https should pass");
	assert.match(truthy(), !encoding.is_https("http://example.com"), "Standard http should fail");
	assert.match(truthy(), !encoding.is_https("ftp://example.com"), "FTP should fail");
	assert.match(truthy(), !encoding.is_https("https"), "Incomplete URL should fail");
});

it('Encoding: is_https - case insensitivity (B4)', () => {
	assert.match(truthy(), encoding.is_https("HTTPS://example.com"), "UPPERCASE HTTPS should pass");
	assert.match(truthy(), encoding.is_https("Https://example.com"), "MixedCase Https should pass");
	assert.match(truthy(), encoding.is_https("htTps://example.com"), "htTps should pass");
});

it('Encoding: is_https - edge cases', () => {
	assert.match(truthy(), !encoding.is_https(null), "null should fail");
	assert.match(truthy(), !encoding.is_https(123), "number should fail");
	assert.match(truthy(), !encoding.is_https({}), "object should fail");
	assert.match(truthy(), !encoding.is_https(""), "empty string should fail");
});
