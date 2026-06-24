import { describe, it, prop, gen, assert, contains, is_type } from 'utest';
import * as web from 'luci_sso.web';

// ─── parse_params ────────────────────────────────────────────────────────────

describe('web: parse_params', () => {
	it('returns empty object for null', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(null));
	});

	it('returns empty object for non-string input', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(42));
	});

	it('returns empty object for empty string', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_params(''));
	});

	it('parses a single key=value pair', () => {
		assert.match(contains({ ok: true, data: { a: '1' } }), web.parse_params('a=1'));
	});

	it('parses multiple pairs', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_params('a=1&b=2'));
	});

	it('stores null for a key with no = separator', () => {
		assert.match(contains({ ok: true, data: { a: null } }), web.parse_params('a'));
	});

	it('stores empty string for a key with trailing =', () => {
		assert.match(contains({ ok: true, data: { a: '' } }), web.parse_params('a='));
	});

	it('decodes + as space', () => {
		assert.match(contains({ ok: true, data: { a: 'hello world' } }), web.parse_params('a=hello+world'));
	});

	it('decodes percent-encoded characters', () => {
		assert.match(contains({ ok: true, data: { a: 'hello world' } }), web.parse_params('a=hello%20world'));
	});

	it('returns INPUT_TOO_LARGE for a string exceeding 16384 characters', () => {
		let big = '';
		for (let i = 0; i < 17; i++)
			big += 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 1000 chars × 17 = 17000 > 16384
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_params(big));
	});

	it('returns INPUT_TOO_LARGE for more than 100 pairs', () => {
		let pairs = [];
		for (let i = 0; i < 101; i++) push(pairs, `p${i}=v`);
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_params(join('&', pairs)));
	});

	prop('never throws and always returns a Result for any ASCII input',
		gen.ascii({ max_len: 300 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) == 0);
			ctx.classify('contains =', index(s, '=') >= 0);
			assert.match(contains({ ok: is_type('bool') }), web.parse_params(s));
		}
	);
});

// ─── parse_cookies ───────────────────────────────────────────────────────────

describe('web: parse_cookies', () => {
	it('returns empty object for null', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(null));
	});

	it('returns empty object for non-string input', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(42));
	});

	it('returns empty object for empty string', () => {
		assert.match(contains({ ok: true, data: {} }), web.parse_cookies(''));
	});

	it('parses a single name=value pair', () => {
		assert.match(contains({ ok: true, data: { a: '1' } }), web.parse_cookies('a=1'));
	});

	it('parses multiple pairs separated by "; "', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_cookies('a=1; b=2'));
	});

	it('parses multiple pairs with no space after semicolon', () => {
		assert.match(contains({ ok: true, data: { a: '1', b: '2' } }), web.parse_cookies('a=1;b=2'));
	});

	it('strips double-quotes from quoted values', () => {
		assert.match(contains({ ok: true, data: { session: 'abc123' } }), web.parse_cookies('session="abc123"'));
	});

	it('stores empty string for a cookie with no value', () => {
		assert.match(contains({ ok: true, data: { a: '' } }), web.parse_cookies('a='));
	});

	it('returns INPUT_TOO_LARGE for a string exceeding 16384 characters', () => {
		let big = '';
		for (let i = 0; i < 17; i++)
			big += 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_cookies(big));
	});

	it('returns INPUT_TOO_LARGE for more than 100 pairs', () => {
		let pairs = [];
		for (let i = 0; i < 101; i++) push(pairs, `c${i}=v`);
		assert.match(contains({ ok: false, error: 'INPUT_TOO_LARGE' }), web.parse_cookies(join('; ', pairs)));
	});

	prop('never throws and always returns a Result for any ASCII input',
		gen.ascii({ max_len: 300 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) == 0);
			ctx.classify('contains ;', index(s, ';') >= 0);
			assert.match(contains({ ok: is_type('bool') }), web.parse_cookies(s));
		}
	);
});
