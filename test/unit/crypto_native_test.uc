import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

test('Native: RS256 Primitive', () => {
	let sig_bin = crypto.b64url_decode(fixtures.RS256.SIG_B64URL);
	assert(native.verify_rs256(fixtures.RS256.MSG, sig_bin, fixtures.RS256.PUBKEY), "Low-level verify should work with binary sig");
});

test('Native: ES256 Primitive', () => {
	let sig_bin = crypto.b64url_decode(fixtures.ES256.SIG_HELLO_B64URL);
	assert(native.verify_es256(fixtures.ES256.MSG, sig_bin, fixtures.ES256.PUBKEY), "Should verify valid ES256 signature");
});

test('Native: HMAC-SHA256 Primitive', () => {
	let key = "secret";
	let msg = "message";
	let mac = native.hmac_sha256(key, msg);
	assert(mac, "Should generate HMAC");
	assert_eq(length(mac), 32, "HMAC should be 32 bytes");
	
	let mac2 = native.hmac_sha256(key, msg);
	assert_eq(mac, mac2, "HMAC should be deterministic");
});

test('Native: SHA-256 Primitive', () => {
	let hash = native.sha256("hello");
	assert_eq(length(hash), 32, "SHA-256 should be 32 bytes");
});

test('Native: Random Primitive', () => {
	let r1 = native.random(32);
	let r2 = native.random(32);
	assert_eq(length(r1), 32);
	assert(r1 != r2);
});
