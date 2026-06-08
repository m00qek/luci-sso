import { it, assert, truthy, is_type } from 'utest';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';

it('crypto: hash - sha256 should return Result object', () => {
	let res = crypto.hash_sha256("test");
	assert.match(is_type("object"), res, "sha256 should return an object, got: " + type(res));
	assert.match(truthy(), res.ok !== undefined, "sha256 should return a Result-like object");
});

it('crypto: hash - sha256_hex should return Result object', () => {
	let res = crypto.hash_sha256_hex("test");
	assert.match(is_type("object"), res, "sha256_hex should return an object");
	assert.match(true, res.ok, "sha256_hex should return a successful Result");
	assert.match(64, length(res.data), "sha256_hex should return 64-char hex string");
});
