import { it, assert, truthy, regex } from 'utest';
import * as encoding from 'luci_sso.encoding';

it('encoding: safe_json - rejects null JSON input', () => {
	let raw = "null";
	let res = encoding.safe_json(raw);

	assert.match(truthy(), !res.ok, "Should NOT be ok when JSON is 'null'");
	assert.match("PARSE_ERROR", res.error, "Error code should be PARSE_ERROR");
	assert.match(regex(/decoded to null/), res.details, "Details should explain null decoding");
});

it('encoding: safe_json - handles valid object', () => {
	let raw = '{"foo": "bar"}';
	let res = encoding.safe_json(raw);

	assert.match(truthy(), res.ok, "Should be ok for valid object");
	assert.match("bar", res.data.foo);
});
