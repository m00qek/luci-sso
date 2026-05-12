import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';

test('crypto: hash - sha256 should return Result object', () => {
	let res = crypto.hash_sha256("test");
	assert(type(res) == "object", "sha256 should return an object, got: " + type(res));
	assert(res.ok !== undefined, "sha256 should return a Result-like object");
});

test('crypto: hash - sha256_hex should return Result object', () => {
	let res = crypto.hash_sha256_hex("test");
	assert(type(res) == "object", "sha256_hex should return an object");
	assert(res.ok === true, "sha256_hex should return a successful Result");
	assert_eq(length(res.data), 64, "sha256_hex should return 64-char hex string");
});
