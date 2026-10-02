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

	it('never leaks raw input fragments on failure (Audit W4)', () => {
		// A parse failure must not echo the offending input back through the error
		// Result — the input can carry secrets (tokens, PII). Guards both a
		// malformed-but-textual payload and raw binary.
		let sensitive = '{"token": "SECRET_1234567890", "garbage": '; // malformed JSON
		let res = encoding.safe_json(sensitive);
		assert.match(contains({ ok: false, error: 'PARSE_ERROR' }), res);
		assert.match(undefined, res.raw_fragment, 'Error Result MUST NOT expose raw_fragment');

		let binary = '\x00\xFF\xDEAD\xBEEF';
		let res2 = encoding.safe_json(binary);
		assert.match(contains({ ok: false }), res2);
		assert.match(undefined, res2.raw_fragment, 'Must not leak binary fragments');
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

// ─── origins (split-horizon) ──────────────────────────────────────────────────

describe('encoding: split_origin', () => {
	it('normalises scheme, host and default port, and keeps the rest verbatim', () => {
		assert.match(contains({ ok: true, data: { origin: 'https://kc.example.com', rest: '/Realms/Home?x=A#f' } }),
			encoding.split_origin('HTTPS://KC.Example.com:443/Realms/Home?x=A#f'));
		assert.match(contains({ ok: true, data: { origin: 'https://kc.example.com:8443', rest: '' } }),
			encoding.split_origin('https://kc.example.com:8443'));
		assert.match(contains({ ok: true, data: { origin: 'http://h', rest: '/' } }), encoding.split_origin('http://h:80/'));
		assert.match(contains({ ok: true, data: { origin: 'https://[fd00::5]:8443', rest: '/p' } }), encoding.split_origin('https://[fd00::5]:8443/p'));
	});

	it('refuses non-URLs and userinfo', () => {
		for (let bad in [ null, '', 'kc.example.com/realms', 'https://', 'https:///path', 'https://user@host/' ])
			assert.match(false, encoding.split_origin(bad).ok, `${bad}`);
	});
});

describe('encoding: is_origin', () => {
	it('accepts scheme://host[:port] with an optional trailing slash', () => {
		for (let good in [ 'https://h', 'https://h/', 'https://h:8443', 'HTTPS://H:8443/' ])
			assert.match(true, encoding.is_origin(good), good);
	});

	it('rejects a path, query or fragment', () => {
		for (let bad in [ 'https://h/p', 'https://h//', 'https://h?q', 'https://h/?q', 'https://h#f', 'h' ])
			assert.match(false, encoding.is_origin(bad), bad);
	});
});

describe('encoding: rebase_origin', () => {
	const ISSUER = 'https://kc.example.com/realms/home';
	const INTERNAL = 'https://10.0.0.5:8443';

	it("moves a URL on the issuer's origin to the internal origin, keeping path and query", () => {
		assert.match('https://10.0.0.5:8443/realms/home/protocol/openid-connect/token?a=1',
			encoding.rebase_origin('https://kc.example.com/realms/home/protocol/openid-connect/token?a=1', ISSUER, INTERNAL));
	});

	it('matches the origin case-insensitively and ignores the default port', () => {
		assert.match('https://10.0.0.5:8443/Certs',
			encoding.rebase_origin('https://KC.EXAMPLE.COM:443/Certs', ISSUER, INTERNAL));
	});

	it('leaves URLs on other origins alone', () => {
		assert.match('https://www.googleapis.com/oauth2/v3/certs',
			encoding.rebase_origin('https://www.googleapis.com/oauth2/v3/certs', 'https://accounts.google.com', INTERNAL));
		assert.match('https://kc.example.com:8443/token',
			encoding.rebase_origin('https://kc.example.com:8443/token', ISSUER, INTERNAL), 'a different port is a different origin');
		assert.match('https://auth.company.com/token',
			encoding.rebase_origin('https://auth.company.com/token', 'https://auth.com', INTERNAL), 'no prefix matching');
	});

	it('is a no-op when the internal origin is the issuer origin, or an argument is not a URL', () => {
		assert.match('https://Kc.example.com/t', encoding.rebase_origin('https://Kc.example.com/t', ISSUER, 'https://kc.example.com/'));
		assert.match('/relative', encoding.rebase_origin('/relative', ISSUER, INTERNAL));
		assert.match(null, encoding.rebase_origin(null, ISSUER, INTERNAL));
	});
});

// ─── log_safe ────────────────────────────────────────────────────────────────

describe('encoding: log_safe', () => {
	it('replaces CR, LF, tabs, escapes and non-ASCII bytes with "?"', () => {
		assert.match('a??b?c?d??|ok', encoding.log_safe("a\r\nb\tc\x1bd\u00e9|ok"));
	});

	it('keeps printable ASCII unchanged', () => {
		assert.match('https://idp.example.com/realms/home?x=1', encoding.log_safe('https://idp.example.com/realms/home?x=1'));
	});

	it('caps the value at 200 bytes by default and marks the cut', () => {
		let long = '';
		for (let i = 0; i < 250; i++) long += 'x';
		let out = encoding.log_safe(long);
		assert.match(203, length(out));
		assert.match('...', substr(out, 200));
	});

	it('honours an explicit cap', () => {
		assert.match('abc...', encoding.log_safe('abcdef', 3));
	});

	it('returns "" for non-strings', () => {
		for (let v in [ null, 42, {}, [] ]) assert.match('', encoding.log_safe(v));
	});

	prop('never emits a byte outside printable ASCII', gen.string({ max_len: 300 }), (s) => {
		return match(encoding.log_safe(s), /[^ -~]/) == null;
	});
});


// ─── return_path ─────────────────────────────────────────────────────────────

describe('encoding: return_path — accepted', () => {
	it('accepts LuCI pages, returning the value unchanged', () => {
		for (let p in [
			'/cgi-bin/luci',
			'/cgi-bin/luci/',
			'/cgi-bin/luci/admin/services/sso',
			'/cgi-bin/luci/admin/status/overview/',
			'/cgi-bin/luci/admin/network/wireless/radio0.network1',
			'/cgi-bin/luci/admin/system/package-manager?query=luci-app_x~1&page=2',
			'/cgi-bin/luci?tab=general',
			'/cgi-bin/luci/admin/a%2Bb,c=d',
		])
			assert.match(contains({ ok: true, data: p }), encoding.return_path(p), p);
	});

	it('accepts a value of exactly 512 bytes', () => {
		let p = '/cgi-bin/luci/';
		while (length(p) < 512) p += 'a';
		assert.match(contains({ ok: true, data: p }), encoding.return_path(p));
	});

	it('accepts a page whose segment only starts like LuCI\'s logout page', () => {
		for (let p in [ '/cgi-bin/luci/admin/logoutx', '/cgi-bin/luci/admin/logout-help', '/cgi-bin/luci/admin/system/logout' ])
			assert.match(contains({ ok: true, data: p }), encoding.return_path(p), p);
	});

	it('accepts a dot inside a segment, which is not a dot segment', () => {
		assert.match(contains({ ok: true }), encoding.return_path('/cgi-bin/luci/admin/a..b/.c/d.'));
	});
});

describe('encoding: return_path — refused', () => {
	const HOSTILE = [
		// Another site
		'https://evil.example/',
		'HTTPS://evil.example/',
		'//evil.example/',
		'///evil.example/',
		'/\\evil.example',
		'\\\\evil.example',
		'javascript:alert(1)',
		'data:text/html,x',
		'evil.example/cgi-bin/luci/',
		'/cgi-bin/luci/@evil.example',
		'/cgi-bin/luci//evil.example',
		'/cgi-bin/luci/admin#//evil.example',
		// Out of LuCI
		'/',
		'/cgi-bin/luci-sso',
		'/cgi-bin/luci-sso/',
		'/cgi-bin/luci-sso/logout',
		'/cgi-bin/luci-sso/callback?code=x',
		'/cgi-bin/lucifer',
		'/cgi-bin/luci/../../evil',
		'/cgi-bin/luci/../luci-sso/logout',
		'/cgi-bin/luci/./admin',
		'/cgi-bin/luci/admin/..',
		'/ubus/',
		'cgi-bin/luci/',
		// LuCI's own logout page
		'/cgi-bin/luci/admin/logout',
		'/cgi-bin/luci/admin/logout/',
		'/cgi-bin/luci/admin/logout?x=1',
		// ...and every path under it: LuCI's dispatcher runs the logout node
		// for those too
		'/cgi-bin/luci/admin/logout/x',
		'/cgi-bin/luci/admin/logout/x/y?z=1',
		'/cgi-bin/luci/admin/logout/admin/status/overview',
		'/cgi-bin/luci/admin/logout%2Fx',
		'/cgi-bin/luci/admin%2Flogout/x',
		'/cgi-bin/luci/admin/logou%74/x',
		'/cgi-bin/luci/admin/logout%252Fx',
		'/cgi-bin/luci/%61dmin/logout/',
		// Percent-encoded tricks
		'%2F%2Fevil.example',
		'/cgi-bin/luci/%2F%2Fevil.example',
		'/cgi-bin/luci/%2f/evil',
		'/cgi-bin/luci/%2e%2e/%2e%2e/',
		'/cgi-bin/luci/%2E%2E/%2E%2E/evil',
		'/cgi-bin/luci/%2e/admin',
		'/cgi-bin/luci/.%2e/luci-sso',
		'/%5Cevil.example',
		'/cgi-bin/luci/%5Cevil',
		'/cgi-bin/luci/%0d%0aSet-Cookie:x',
		'/cgi-bin/luci/%0D%0ALocation:%20https://evil',
		'/cgi-bin/luci/%00',
		'/cgi-bin/luci/%09',
		'/cgi-bin/luci/%40evil',
		'/cgi-bin/luci/%3a',
		'/cgi-bin/luci/%23x',
		'/cgi-bin/luci/%C3%A9',
		'/cgi-bin/luci/admin%2F..%2F..%2Fevil',
		'/cgi-bin/luci/a?next=%2F%2Fevil',
		// Double and deeper encoding
		'/cgi-bin/luci/%252e%252e/%252e%252e/evil',
		'/cgi-bin/luci/%252F%252Fevil',
		'/cgi-bin/luci/%255C',
		'/cgi-bin/luci/%250d%250a',
		'/cgi-bin/luci/%25252e',
		'/cgi-bin/luci/%2525252e',
		// Malformed escapes
		'/cgi-bin/luci/%',
		'/cgi-bin/luci/%2',
		'/cgi-bin/luci/%zz',
		'/cgi-bin/luci/%25zz',
		// Raw control characters, whitespace and other bytes
		'/cgi-bin/luci/\r\nSet-Cookie:x',
		'/cgi-bin/luci/\nx',
		'/cgi-bin/luci/\tx',
		'/cgi-bin/luci/\u0000x',
		'/cgi-bin/luci/ x',
		'/cgi-bin/luci/"x',
		'/cgi-bin/luci/<script>',
		'/cgi-bin/luci/admin/x%20y',
		'/cgi-bin/luci/;stok=x',
		// Unicode
		'/cgi-bin/luci/é',
		'/cgi-bin/luci/∕∕evil',
		'/cgi-bin/luci/／／evil',
		'。/evil',
	];

	it('refuses every hostile value', () => {
		for (let v in HOSTILE)
			assert.match(contains({ ok: false, error: 'INVALID_RETURN_PATH' }), encoding.return_path(v), v);
	});

	it('refuses an empty value', () => {
		assert.match(contains({ ok: false, error: 'INVALID_RETURN_PATH', details: 'empty' }), encoding.return_path(''));
	});

	it('refuses a value over 512 bytes', () => {
		let p = '/cgi-bin/luci/';
		while (length(p) < 513) p += 'a';
		assert.match(contains({ ok: false, details: 'longer than 512 bytes' }), encoding.return_path(p));
	});

	it('refuses a non-string', () => {
		for (let v in [ null, 42, true, [ '/cgi-bin/luci/' ], { path: '/cgi-bin/luci/' } ])
			assert.match(contains({ ok: false, error: 'INVALID_RETURN_PATH', details: 'not a string' }), encoding.return_path(v));
	});

	it('names the reason', () => {
		assert.match(contains({ details: 'not a LuCI page' }),                         encoding.return_path('/evil'));
		assert.match(contains({ details: 'contains //' }),                             encoding.return_path('/cgi-bin/luci//evil'));
		assert.match(contains({ details: 'contains a dot segment' }),                  encoding.return_path('/cgi-bin/luci/%2e%2e/'));
		assert.match(contains({ details: 'holds a character outside the allowed set' }), encoding.return_path('/cgi-bin/luci/%5C'));
		assert.match(contains({ details: 'has a malformed percent escape' }),          encoding.return_path('/cgi-bin/luci/%zz'));
		assert.match(contains({ details: 'percent-encoded too many times' }),          encoding.return_path('/cgi-bin/luci/%2525252e'));
		assert.match(contains({ details: "is LuCI's logout page" }),                   encoding.return_path('/cgi-bin/luci/admin/logout'));
		assert.match(contains({ details: "is LuCI's logout page" }),                   encoding.return_path('/cgi-bin/luci/admin/logout/x'));
		assert.match(contains({ details: "is LuCI's logout page" }),                   encoding.return_path('/cgi-bin/luci/admin/logout%2Fx'));
	});

	prop('anything accepted is a LuCI path with only allowed characters and no //', gen.string({ max_len: 80 }), (s, ctx) => {
		for (let v in [ s, '/cgi-bin/luci/' + s ]) {
			let res = encoding.return_path(v);
			ctx.classify('accepted', res.ok);
			if (!res.ok) continue;
			assert.match(v, res.data);
			assert.match(regex(/^\/cgi-bin\/luci(\/|\?|$)/), v);
			assert.match(regex(/^[A-Za-z0-9\/_.~%?&=+,-]+$/), v);
			assert.match(-1, index(v, '//'));
		}
	});

	prop('nothing under LuCI\'s logout page is accepted, encoded or not', gen.string({ max_len: 40 }), (s) => {
		for (let v in [ '/cgi-bin/luci/admin/logout/' + s, '/cgi-bin/luci/admin/logout%2F' + s, '/cgi-bin/luci/admin/logout%252F' + s ])
			assert.match(contains({ ok: false }), encoding.return_path(v), v);
	});
});
