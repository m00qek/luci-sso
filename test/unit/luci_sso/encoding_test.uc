import { describe, it, prop, gen, assert, contains, regex } from 'utest';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

// RFC 4648 §10 test vectors (base64url = standard base64 with no padding, + → -, / → _)
const VECTORS = [
	{ raw: '',       b64url: ''         },
	{ raw: 'f',      b64url: 'Zg'       },
	{ raw: 'fo',     b64url: 'Zm8'      },
	{ raw: 'foo',    b64url: 'Zm9v'     },
	{ raw: 'foobar', b64url: 'Zm9vYmFy' },
];

// Bytes that map to + and / in standard base64 — must become - and _ in base64url.
// '\x00\x00>' (0x00 0x00 0x3E) → AAA+ standard → AAA- b64url
// '\x00\x00?' (0x00 0x00 0x3F) → AAA/ standard → AAA_ b64url
const URLSAFE = { raw: '\x00\x00>\x00\x00?', b64url: 'AAA-AAA_' };

// ─── b64url_encode ───────────────────────────────────────────────────────────

describe('encoding: b64url_encode', () => {
	it('dies on non-string input', () => {
		assert.throws(() => encoding.b64url_encode(null),  /CONTRACT_VIOLATION/);
		assert.throws(() => encoding.b64url_encode(42),    /CONTRACT_VIOLATION/);
	});

	it('RFC 4648 known vectors', () => {
		for (let v in VECTORS)
			assert.match(contains({ ok: true, data: v.b64url }), encoding.b64url_encode(v.raw));
	});

	it('maps standard base64 + and / to - and _', () => {
		assert.match(contains({ ok: true, data: URLSAFE.b64url }), encoding.b64url_encode(URLSAFE.raw));
	});

	it('never emits padding characters', () => {
		for (let v in VECTORS)
			assert.match(-1, index(encoding.b64url_encode(v.raw).data, '='));
	});

	prop('output only contains base64url characters', gen.string({ max_len: 200 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		assert.match(contains({ ok: true, data: regex(/^[A-Za-z0-9_-]*$/) }), encoding.b64url_encode(s));
	});
});

// ─── b64url_decode ───────────────────────────────────────────────────────────

describe('encoding: b64url_decode', () => {
	it('dies on non-string input', () => {
		assert.throws(() => encoding.b64url_decode(null), /CONTRACT_VIOLATION/);
		assert.throws(() => encoding.b64url_decode(42),   /CONTRACT_VIOLATION/);
	});

	it('returns TOKEN_TOO_LARGE for input exceeding 32 KB', () => {
		let huge = '';
		for (let i = 0; i < 32769; i++) huge += 'A';
		assert.match(contains({ ok: false, error: 'TOKEN_TOO_LARGE' }), encoding.b64url_decode(huge));
	});

	it('RFC 4648 known vectors', () => {
		for (let v in VECTORS)
			assert.match(contains({ ok: true, data: v.raw }), encoding.b64url_decode(v.b64url));
	});

	it('decodes - and _ back to the original bytes', () => {
		assert.match(contains({ ok: true, data: URLSAFE.raw }), encoding.b64url_decode(URLSAFE.b64url));
	});

	it('returns INVALID_ENCODING for standard base64 + character', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ENCODING' }), encoding.b64url_decode('A+B='));
	});

	it('returns INVALID_ENCODING for standard base64 / character', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ENCODING' }), encoding.b64url_decode('A/B='));
	});

	it('returns INVALID_ENCODING for = padding characters', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ENCODING' }), encoding.b64url_decode('Zg=='));
	});

	it('returns INVALID_ENCODING for arbitrary non-alphabet characters', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ENCODING' }), encoding.b64url_decode('!!!!'));
	});
});

// ─── encode / decode roundtrip ───────────────────────────────────────────────

describe('encoding: b64url roundtrip', () => {
	prop('decode(encode(s)) == s for any string', gen.string({ max_len: 200 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		let enc = encoding.b64url_encode(s);
		assert.match(contains({ ok: true }), enc);
		assert.match(contains({ ok: true, data: s }), encoding.b64url_decode(enc.data));
	});
});

// ─── binary_truncate ─────────────────────────────────────────────────────────

describe('encoding: binary_truncate', () => {
	it('dies when data is not a string', () => {
		assert.throws(() => encoding.binary_truncate(null, 2), /CONTRACT_VIOLATION/);
		assert.throws(() => encoding.binary_truncate(42,   2), /CONTRACT_VIOLATION/);
	});

	it('dies when len is not an integer', () => {
		assert.throws(() => encoding.binary_truncate('hello', '3'), /CONTRACT_VIOLATION/);
		assert.throws(() => encoding.binary_truncate('hello', 1.5), /CONTRACT_VIOLATION/);
	});

	it('dies when len exceeds the data length', () => {
		assert.throws(() => encoding.binary_truncate('hi', 3), /CONTRACT_VIOLATION/);
		assert.throws(() => encoding.binary_truncate('hi', 3), /truncation length exceeds data length/);
	});

	it('returns the first N bytes', () => {
		assert.match(contains({ ok: true, data: 'hel' }), encoding.binary_truncate('hello', 3));
	});

	it('len == length(data) returns the full string', () => {
		assert.match(contains({ ok: true, data: 'hello' }), encoding.binary_truncate('hello', 5));
	});

	it('len == 0 returns an empty string', () => {
		assert.match(contains({ ok: true, data: '' }), encoding.binary_truncate('hello', 0));
	});

	it('preserves null bytes in binary data', () => {
		assert.match(contains({ ok: true, data: '\x00\x01' }), encoding.binary_truncate('\x00\x01\x02', 2));
	});
});

// ─── safe_json ───────────────────────────────────────────────────────────────

describe('encoding: safe_json', () => {
	it('parses a valid JSON object string', () => {
		assert.match(contains({ ok: true, data: { a: 1 } }), encoding.safe_json('{"a":1}'));
	});

	it('parses a JSON array string', () => {
		assert.match(contains({ ok: true, data: [1, 2, 3] }), encoding.safe_json('[1,2,3]'));
	});

	it('returns PARSE_ERROR for invalid JSON', () => {
		assert.match(contains({ ok: false, error: 'PARSE_ERROR' }), encoding.safe_json('not json'));
	});

	it('returns PARSE_ERROR when JSON decodes to null', () => {
		// json('null') returns null, which safe_json treats as a parse error
		assert.match(contains({ ok: false, error: 'PARSE_ERROR' }), encoding.safe_json('null'));
	});

	it('returns INVALID_TYPE for null input', () => {
		assert.match(contains({ ok: false, error: 'INVALID_TYPE' }), encoding.safe_json(null));
	});

	it('returns INVALID_TYPE for integer input', () => {
		assert.match(contains({ ok: false, error: 'INVALID_TYPE' }), encoding.safe_json(42));
	});

	it('unwraps a Result.ok and parses the data', () => {
		assert.match(contains({ ok: true, data: { b: 2 } }), encoding.safe_json(Result.ok('{"b":2}')));
	});

	it('short-circuits a Result.err without parsing', () => {
		assert.match(contains({ ok: false, error: 'UPSTREAM_ERROR' }), encoding.safe_json(Result.err('UPSTREAM_ERROR')));
	});

	it('calls .read() on stream-like objects and parses the result', () => {
		assert.match(contains({ ok: true, data: { c: 3 } }), encoding.safe_json({ read: () => '{"c":3}' }));
	});
});

// ─── normalize_url ───────────────────────────────────────────────────────────

describe('encoding: normalize_url', () => {
	it('returns INVALID_ARGUMENT for non-string input', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), encoding.normalize_url(null));
		assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), encoding.normalize_url(42));
	});

	it('returns MALFORMED_URL for a string without a scheme', () => {
		assert.match(contains({ ok: false, error: 'MALFORMED_URL' }), encoding.normalize_url('example.com'));
	});

	it('returns MALFORMED_URL for an empty string', () => {
		assert.match(contains({ ok: false, error: 'MALFORMED_URL' }), encoding.normalize_url(''));
	});

	it('strips a trailing slash', () => {
		assert.match(contains({ ok: true, data: 'https://example.com' }), encoding.normalize_url('https://example.com/'));
	});

	it('strips multiple trailing slashes', () => {
		assert.match(contains({ ok: true, data: 'https://example.com' }), encoding.normalize_url('https://example.com///'));
	});

	it('lowercases the scheme', () => {
		assert.match(contains({ ok: true, data: 'https://example.com' }), encoding.normalize_url('HTTPS://example.com'));
	});

	it('lowercases the host', () => {
		assert.match(contains({ ok: true, data: 'https://example.com' }), encoding.normalize_url('https://EXAMPLE.COM'));
	});

	it('preserves path case', () => {
		assert.match(contains({ ok: true, data: 'https://example.com/Path/To' }), encoding.normalize_url('https://example.com/Path/To'));
	});

	it('strips default port 443 for https', () => {
		assert.match(contains({ ok: true, data: 'https://example.com/api' }), encoding.normalize_url('https://example.com:443/api'));
	});

	it('strips default port 80 for http', () => {
		assert.match(contains({ ok: true, data: 'http://example.com' }), encoding.normalize_url('http://example.com:80'));
	});

	it('preserves a non-default port', () => {
		assert.match(contains({ ok: true, data: 'https://example.com:8080' }), encoding.normalize_url('https://example.com:8080'));
	});

	it('does not strip port 443 for http (wrong scheme)', () => {
		assert.match(contains({ ok: true, data: 'http://example.com:443' }), encoding.normalize_url('http://example.com:443'));
	});

	it('does not strip port 80 for https (wrong scheme)', () => {
		assert.match(contains({ ok: true, data: 'https://example.com:80' }), encoding.normalize_url('https://example.com:80'));
	});

	it('is idempotent', () => {
		for (let url in [
			'https://example.com/',
			'HTTPS://EXAMPLE.COM/path',
			'http://example.com:80',
			'https://example.com:443/api/',
			'https://example.com:8080/path',
		]) {
			let once = encoding.normalize_url(url);
			assert.match(contains({ ok: true }), once);
			assert.match(once.data, encoding.normalize_url(once.data).data);
		}
	});
});

// ─── normalize_sub ───────────────────────────────────────────────────────────

describe('encoding: normalize_sub', () => {
	it('returns INVALID_ARGUMENT for non-string input', () => {
		assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), encoding.normalize_sub(null));
		assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), encoding.normalize_sub(42));
	});

	it('lowercases the sub claim', () => {
		assert.match(contains({ ok: true, data: 'user@example.com' }), encoding.normalize_sub('User@Example.COM'));
	});

	it('leaves already-lowercase input unchanged', () => {
		assert.match(contains({ ok: true, data: 'alice' }), encoding.normalize_sub('alice'));
	});

	it('handles an empty string', () => {
		assert.match(contains({ ok: true, data: '' }), encoding.normalize_sub(''));
	});

	prop('result is always lowercase', gen.string({ max_len: 100 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		let res = encoding.normalize_sub(s);
		assert.match(contains({ ok: true }), res);
		assert.match(lc(s), res.data);
	});

	prop('is idempotent', gen.string({ max_len: 100 }), (s) => {
		let once = encoding.normalize_sub(s);
		assert.match(contains({ ok: true }), once);
		assert.match(once.data, encoding.normalize_sub(once.data).data);
	});
});

// ─── is_https ────────────────────────────────────────────────────────────────

describe('encoding: is_https', () => {
	it('returns true for a lowercase https URL', () => {
		assert.match(true, encoding.is_https('https://example.com'));
	});

	it('returns true for an uppercase HTTPS scheme (case-insensitive)', () => {
		assert.match(true, encoding.is_https('HTTPS://example.com'));
	});

	it('returns true for mixed-case scheme', () => {
		assert.match(true, encoding.is_https('Https://example.com'));
	});

	it('returns false for http', () => {
		assert.match(false, encoding.is_https('http://example.com'));
	});

	it('returns false for ftp', () => {
		assert.match(false, encoding.is_https('ftp://example.com'));
	});

	it('returns false for null', () => {
		assert.match(false, encoding.is_https(null));
	});

	it('returns false for an empty string', () => {
		assert.match(false, encoding.is_https(''));
	});

	it('returns false for a scheme-only string without ://', () => {
		assert.match(false, encoding.is_https('https'));
	});

	it('returns false for a string that merely contains https', () => {
		assert.match(false, encoding.is_https('redirect to https://example.com'));
	});
});
