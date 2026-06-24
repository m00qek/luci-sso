import { describe, it, prop, gen, assert } from 'utest';
import * as Result from 'luci_sso.result';

// ─── ok ──────────────────────────────────────────────────────────────────────

describe('result: ok', () => {
	it('ok field is true', () => {
		assert.match(true, Result.ok('x').ok);
	});

	it('stores a string', () => {
		assert.match('hello', Result.ok('hello').data);
	});

	it('stores a number', () => {
		assert.match(42, Result.ok(42).data);
	});

	it('stores an object (field access)', () => {
		assert.match('v', Result.ok({ k: 'v' }).data.k);
	});

	it('stores null', () => {
		assert.match(null, Result.ok(null).data);
	});

	it('stores an empty string', () => {
		assert.match('', Result.ok('').data);
	});

	it('is recognised by Result.is()', () => {
		assert.match(true, Result.is(Result.ok('x')));
	});

	prop('ok preserves any string payload exactly', gen.string({ max_len: 100 }), (s) => {
		assert.match(s, Result.ok(s).data);
	});
});

// ─── err ─────────────────────────────────────────────────────────────────────

describe('result: err', () => {
	it('ok field is false', () => {
		assert.match(false, Result.err('CODE').ok);
	});

	it('stores the error code', () => {
		assert.match('MY_ERROR', Result.err('MY_ERROR').error);
	});

	it('stores details when provided', () => {
		assert.match('extra', Result.err('CODE', 'extra').details);
	});

	it('details is null when omitted', () => {
		assert.match(null, Result.err('CODE').details);
	});

	it('stores an object as details', () => {
		assert.match(3, Result.err('CODE', { line: 3 }).details.line);
	});

	it('is recognised by Result.is()', () => {
		assert.match(true, Result.is(Result.err('CODE')));
	});

	prop('err preserves any alphanumeric error code exactly', gen.alphanumeric({ min_len: 1, max_len: 30 }), (code) => {
		assert.match(code, Result.err(code).error);
	});
});

// ─── is ──────────────────────────────────────────────────────────────────────

describe('result: is', () => {
	it('returns false for a plain object shaped like ok', () => {
		// prototype check distinguishes Result instances from plain objects
		assert.match(false, Result.is({ ok: true, data: 'x' }));
	});

	it('returns false for a plain object shaped like err', () => {
		assert.match(false, Result.is({ ok: false, error: 'E' }));
	});

	it('returns false for null', () => {
		assert.match(false, Result.is(null));
	});

	it('returns false for a string', () => {
		assert.match(false, Result.is('result'));
	});

	it('returns false for a number', () => {
		assert.match(false, Result.is(42));
	});

	it('returns false for an array', () => {
		assert.match(false, Result.is([]));
	});
});
