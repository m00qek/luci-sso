import { describe, it, prop, gen, assert, contains } from 'utest';
import * as real_native from 'luci_sso.native';
import * as jws from 'luci_sso.crypto.jws';
import * as encoding from 'luci_sso.encoding';

// A fixed 32-byte HMAC secret for deterministic tests
const SECRET = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
               '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f';

const broken = { hmac_sha256: () => null };

function tamper(token, part_idx) {
	let parts = split(token, '.');
	let s = parts[part_idx];
	// Flip the last character within the base64url alphabet
	let last = substr(s, length(s) - 1, 1);
	let replacement = (last == 'A') ? 'B' : 'A';
	parts[part_idx] = substr(s, 0, length(s) - 1) + replacement;
	return join('.', parts);
}

// ─── sign ────────────────────────────────────────────────────────────────────

describe('crypto.jws: sign', () => {
	it('dies when payload is not an object', () => {
		assert.throws(() => jws.sign(real_native, 'string', SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(real_native, null, SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(real_native, 42, SECRET), /CONTRACT_VIOLATION/);
	});

	it('dies when secret is not a string', () => {
		assert.throws(() => jws.sign(real_native, {}, null), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(real_native, {}, 42), /CONTRACT_VIOLATION/);
	});

	it('returns Result.ok with a three-part dot-separated compact serialization', () => {
		let res = jws.sign(real_native, { sub: '123' }, SECRET);
		assert.match(contains({ ok: true }), res);
		assert.match(3, length(split(res.data, '.')));
	});

	it('header encodes alg=HS256 typ=JWT', () => {
		let res = jws.sign(real_native, { sub: '123' }, SECRET);
		assert.match(contains({ ok: true }), res);
		let decoded = encoding.b64url_decode(split(res.data, '.')[0]);
		assert.match(contains({ ok: true }), decoded);
		let header = json(decoded.data);
		assert.match('HS256', header.alg);
		assert.match('JWT', header.typ);
	});

	it('returns CRYPTO_ERROR when native.hmac_sha256 fails', () => {
		assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), jws.sign(broken, { sub: '123' }, SECRET));
	});
});

// ─── verify ──────────────────────────────────────────────────────────────────

describe('crypto.jws: verify', () => {
	it('dies when token is not a string', () => {
		assert.throws(() => jws.verify(real_native, null, SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.verify(real_native, 42, SECRET), /CONTRACT_VIOLATION/);
	});

	it('dies when secret is not a string', () => {
		assert.throws(() => jws.verify(real_native, 'tok', null), /CONTRACT_VIOLATION/);
	});

	it('returns TOKEN_TOO_LARGE for tokens exceeding 16 KB', () => {
		let huge = '';
		for (let i = 0; i < 16385; i++) huge += 'a';
		assert.match(contains({ ok: false, error: 'TOKEN_TOO_LARGE' }), jws.verify(real_native, huge, SECRET));
	});

	it('returns MALFORMED_JWS for tokens without exactly 3 parts', () => {
		for (let tok in ['onlyone', 'two.parts', 'four.parts.too.many']) {
			assert.match(contains({ ok: false, error: 'MALFORMED_JWS' }), jws.verify(real_native, tok, SECRET));
		}
	});

	it('returns INVALID_HEADER_ENCODING for non-base64url header', () => {
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_ENCODING' }), jws.verify(real_native, '!!!.payload.sig', SECRET));
	});

	it('returns INVALID_HEADER_JSON for non-JSON header', () => {
		let h = encoding.b64url_encode('not json').data;
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_JSON' }), jws.verify(real_native, `${h}.payload.sig`, SECRET));
	});

	it('returns UNSUPPORTED_ALGORITHM for non-HS256 alg', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }), jws.verify(real_native, `${h}.payload.sig`, SECRET));
	});

	it('returns INVALID_SIGNATURE_ENCODING for a non-base64url signature', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jws.verify(real_native, `${h}.${p}.!!!`, SECRET));
	});

	it('returns INVALID_PAYLOAD_ENCODING for a payload that is not valid base64url', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let bad_p = '!!!';
		let sig = encoding.b64url_encode(real_native.hmac_sha256(SECRET, h + '.' + bad_p)).data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_ENCODING' }), jws.verify(real_native, `${h}.${bad_p}.${sig}`, SECRET));
	});

	it('returns INVALID_PAYLOAD_JSON for a payload that decodes but is not valid JSON', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let bad_p = encoding.b64url_encode('not-json').data;
		let sig = encoding.b64url_encode(real_native.hmac_sha256(SECRET, h + '.' + bad_p)).data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_JSON' }), jws.verify(real_native, `${h}.${bad_p}.${sig}`, SECRET));
	});

	it('returns INVALID_SIGNATURE for a tampered payload', () => {
		let token = jws.sign(real_native, { sub: '123', data: 'ok' }, SECRET).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE' }), jws.verify(real_native, tamper(token, 1), SECRET));
	});

	it('returns INVALID_SIGNATURE for a tampered signature', () => {
		let token = jws.sign(real_native, { sub: '456' }, SECRET).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE' }), jws.verify(real_native, tamper(token, 2), SECRET));
	});

	it('returns INVALID_SIGNATURE when verified with a different secret', () => {
		let token = jws.sign(real_native, { sub: '789' }, SECRET).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE' }), jws.verify(real_native, token, SECRET + 'x'));
	});
});

// ─── sign → verify roundtrip ─────────────────────────────────────────────────

describe('crypto.jws: sign/verify roundtrip', () => {
	it('roundtrip restores the original payload', () => {
		let payload = { sub: 'user-1', exp: 9999999999, custom: 'value' };
		let token = jws.sign(real_native, payload, SECRET);
		assert.match(contains({ ok: true }), token);
		assert.match(
			contains({ ok: true, data: contains({ sub: payload.sub, exp: payload.exp, custom: payload.custom }) }),
			jws.verify(real_native, token.data, SECRET)
		);
	});

	prop('roundtrip holds for any object payload and any string secret',
		gen.record({
			payload: gen.record({
				sub:   gen.alphanumeric({ min_len: 1, max_len: 20 }),
				value: gen.int(0, 1000000),
			}),
			secret: gen.string({ min_len: 1, max_len: 64 }),
		}),
		(r, ctx) => {
			ctx.classify('short secret (≤8)',  length(r.secret) <= 8);
			ctx.classify('long secret (>32)',  length(r.secret) > 32);
			let signed = jws.sign(real_native, r.payload, r.secret);
			assert.match(contains({ ok: true }), signed);
			assert.match(
				contains({ ok: true, data: contains({ sub: r.payload.sub, value: r.payload.value }) }),
				jws.verify(real_native, signed.data, r.secret)
			);
		}
	);

	prop('wrong secret always rejects',
		gen.record({
			payload: gen.record({ id: gen.int(1, 9999) }),
			secret:  gen.string({ min_len: 1, max_len: 32 }),
			other:   gen.string({ min_len: 1, max_len: 32 }),
		}),
		(r, ctx) => {
			if (r.secret == r.other) return;
			ctx.classify('same length', length(r.secret) === length(r.other));
			let signed = jws.sign(real_native, r.payload, r.secret);
			assert.match(contains({ ok: true }), signed);
			assert.match(
				contains({ ok: false, error: 'INVALID_SIGNATURE' }),
				jws.verify(real_native, signed.data, r.other)
			);
		}
	);
});
