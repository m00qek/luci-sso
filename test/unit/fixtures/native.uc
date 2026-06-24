/**
 * Fixtures for native conformance tests.
 *
 * All cryptographic values are verified with OpenSSL.
 * JWK binary parameters were extracted from the corresponding PEM keys using:
 *   openssl rsa  -pubin -in pub.pem -text -noout   (for RSA n/e)
 *   openssl ec   -pubin -in pub.pem -text -noout   (for EC x/y)
 */

import * as encoding from 'luci_sso.encoding';
import { PLUMBING_RSA } from 'tier1.fixtures';
import { EC_256 } from 'tier0.fixtures';

export const hex_to_bin = function(h) {
	let s = '';
	for (let i = 0; i < length(h); i += 2)
		s += chr(hex(substr(h, i, 2)));
	return s;
};

// RSA-2048 JWK parameters for PLUMBING_RSA.pubkey.
// base64url(n) and base64url(e) are the modulus and public exponent of that key.
export const RSA_JWK_N = 'q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8' +
	'-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3X' +
	'Q7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94' +
	'VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L' +
	'9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm-qCNLXxS' +
	'cFg-X7xcW91pQ';

export const JWK_RSA = {
	n_bin: encoding.b64url_decode(RSA_JWK_N).data,
	e_bin: encoding.b64url_decode('AQAB').data,
	pem:   PLUMBING_RSA.pubkey,
};

// EC P-256 JWK parameters for EC_256.pub.
// x/y are the uncompressed point coordinates (32 bytes each).
export const JWK_EC = {
	x_bin: hex_to_bin('2ca49943de78ced53c36683e3d90df1668bff173597f85daa7d6804e4c659cce'),
	y_bin: hex_to_bin('141ed122e7bcffa24d35e37c81830bf9b8006a9acbf60fcdf80a862405e357fb'),
	pem:   EC_256.pub,
};

// Base64url-encoded coordinates for JWK_EC (for use with jwk.to_pem which takes b64url strings)
export const JWK_EC_X_B64 = encoding.b64url_encode(JWK_EC.x_bin).data;
export const JWK_EC_Y_B64 = encoding.b64url_encode(JWK_EC.y_bin).data;
