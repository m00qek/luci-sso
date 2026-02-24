import { test, assert, assert_eq, assert_match } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('encoding: safe_json - rejects null JSON input', () => {
	let raw = "null";
	let res = encoding.safe_json(raw);
	
	assert(!res.ok, "Should NOT be ok when JSON is 'null'");
	assert_eq(res.error, "PARSE_ERROR", "Error code should be PARSE_ERROR");
	assert_match(res.details, /decoded to null/, "Details should explain null decoding");
});

test('encoding: safe_json - handles valid object', () => {
	let raw = '{"foo": "bar"}';
	let res = encoding.safe_json(raw);
	
	assert(res.ok, "Should be ok for valid object");
	assert_eq(res.data.foo, "bar");
});
