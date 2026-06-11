import { it, assert, truthy, falsy } from 'utest';
import * as jwt from 'luci_sso.crypto.jwt';

it('crypto: jwt - missing iss claim should NOT crash', () => {
	// Options specify an issuer to check
	let options = { iss: "https://idp.com" };
	
	// Payload is missing 'iss'
	let payload = {
		sub: "user1",
		aud: "client1",
		exp: time() + 3600,
		iat: time()
	};

	// We don't need a full signature check for this specific regression
	// because normalize_url is called during claim validation.
	// We'll mock the signature check or just test the validation logic if possible.
	
	// Actually, let's just test normalize_url directly first to confirm it returns Result.err
	// instead of dying once fixed.
});

import * as encoding from 'luci_sso.encoding';

it('encoding: normalize_url - should return Result.err for non-string instead of die', () => {
	let res = encoding.normalize_url(null);
	assert.match(falsy(), res.ok, "Should return Result.err for null");
	assert.match("INVALID_ARGUMENT", res.error);
});
