import { describe, it, prop, gen, assert, contains, mock, spy } from 'utest';
import * as jws from 'luci_sso.crypto.jws';
import * as encoding from 'luci_sso.encoding';

// jws.sign/verify fake `native` (data-first) so these tests exercise only the
// wrapper: contract guards, the compact serialization format, forwarding to
// native.hmac_sha256, the recompute-and-compare signature check, and the error
// taxonomy. That HMAC actually differs for distinct secrets/messages is a
// native-crypto property covered in test/native.

function unhex(h) {
	let s = '';
	for (let i = 0; i < length(h); i += 2) s += chr(hex(substr(h, i, 2)));
	return s;
}

const SECRET = 'a-32-byte-secret-key-for-hmac!!!';

// Canned MAC returned by the faked native.hmac_sha256 for every call.
const MAC     = unhex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
const MAC_SIG = encoding.b64url_encode(MAC).data; // the base64url signature sign() will embed

// native.hmac_sha256 always returns the canned MAC (data-first).
function with_mac(fn) {
	mock.inject('native', { strict: true, data: { hmac_sha256: MAC } }, fn);
}

// native must never be called — any call dies (strict, no data).
function with_strict(fn) {
	mock.inject('native', { strict: true }, fn);
}

// ─── sign ────────────────────────────────────────────────────────────────────

describe('crypto.jws: sign', () => {
	it('dies when payload is not an object', () => with_strict((native) => {
		assert.throws(() => jws.sign(native, 'string', SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(native, null, SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(native, 42, SECRET), /CONTRACT_VIOLATION/);
	}));

	it('dies when secret is not a string', () => with_strict((native) => {
		assert.throws(() => jws.sign(native, {}, null), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.sign(native, {}, 42), /CONTRACT_VIOLATION/);
	}));

	it('returns Result.ok with a three-part dot-separated compact serialization', () => with_mac((native) => {
		let res = jws.sign(native, { sub: '123' }, SECRET);
		assert.match(contains({ ok: true }), res);
		assert.match(3, length(split(res.data, '.')));
	}));

	it('header encodes alg=HS256 typ=JWT', () => with_mac((native) => {
		let res = jws.sign(native, { sub: '123' }, SECRET);
		assert.match(contains({ ok: true }), res);
		let decoded = encoding.b64url_decode(split(res.data, '.')[0]);
		assert.match(contains({ ok: true }), decoded);
		let header = json(decoded.data);
		assert.match('HS256', header.alg);
		assert.match('JWT', header.typ);
	}));

	it('forwards the secret and header.payload to native.hmac_sha256 and embeds its output', () => with_mac((native) => {
		let res = jws.sign(native, { sub: '123' }, SECRET);
		assert.match(contains({ ok: true }), res);
		let parts = split(res.data, '.');
		// the embedded signature is base64url(MAC)
		assert.match(MAC_SIG, parts[2]);
		// native.hmac_sha256(secret, header + '.' + payload)
		let call = spy(native).calls.hmac_sha256[0];
		assert.match(SECRET, call[0]);
		assert.match(`${parts[0]}.${parts[1]}`, call[1]);
	}));

	it('returns CRYPTO_ERROR when native.hmac_sha256 fails', () => {
		mock.inject('native', { strict: true, data: { hmac_sha256: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), jws.sign(native, { sub: '123' }, SECRET));
		});
	});
});

// ─── verify ──────────────────────────────────────────────────────────────────

describe('crypto.jws: verify', () => {
	it('dies when token is not a string', () => with_strict((native) => {
		assert.throws(() => jws.verify(native, null, SECRET), /CONTRACT_VIOLATION/);
		assert.throws(() => jws.verify(native, 42, SECRET), /CONTRACT_VIOLATION/);
	}));

	it('dies when secret is not a string', () => with_strict((native) => {
		assert.throws(() => jws.verify(native, 'tok', null), /CONTRACT_VIOLATION/);
	}));

	it('returns TOKEN_TOO_LARGE for tokens exceeding 16 KB', () => with_strict((native) => {
		let huge = '';
		for (let i = 0; i < 16385; i++) huge += 'a';
		assert.match(contains({ ok: false, error: 'TOKEN_TOO_LARGE' }), jws.verify(native, huge, SECRET));
	}));

	it('returns MALFORMED_JWS for tokens without exactly 3 parts', () => with_strict((native) => {
		for (let tok in ['onlyone', 'two.parts', 'four.parts.too.many']) {
			assert.match(contains({ ok: false, error: 'MALFORMED_JWS' }), jws.verify(native, tok, SECRET));
		}
	}));

	it('tolerates unknown header fields (forward compatibility)', () => with_mac((native) => {
		// Extra/unrecognised header members must not break verification, as long as
		// alg is supported and the signature checks out.
		let header  = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT', kid: 'k1', malicious_extra: 'ignore-me' })).data;
		let payload = encoding.b64url_encode(sprintf('%J', { foo: 'bar' })).data;
		let token   = `${header}.${payload}.${MAC_SIG}`;
		assert.match(contains({ ok: true, data: contains({ foo: 'bar' }) }), jws.verify(native, token, SECRET));
	}));

	it('returns INVALID_HEADER_ENCODING for non-base64url header', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_ENCODING' }), jws.verify(native, '!!!.payload.sig', SECRET));
	}));

	it('returns INVALID_HEADER_JSON for non-JSON header', () => with_strict((native) => {
		let h = encoding.b64url_encode('not json').data;
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_JSON' }), jws.verify(native, `${h}.payload.sig`, SECRET));
	}));

	it('returns UNSUPPORTED_ALGORITHM for non-HS256 alg', () => with_strict((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }), jws.verify(native, `${h}.payload.sig`, SECRET));
	}));

	it('returns INVALID_SIGNATURE_ENCODING for a non-base64url signature', () => with_strict((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jws.verify(native, `${h}.${p}.!!!`, SECRET));
	}));

	it('forwards the secret and header.payload to native.hmac_sha256', () => with_mac((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		jws.verify(native, `${h}.${p}.${MAC_SIG}`, SECRET);
		let call = spy(native).calls.hmac_sha256[0];
		assert.match(SECRET, call[0]);
		assert.match(`${h}.${p}`, call[1]);
	}));

	it('returns INVALID_SIGNATURE when the embedded signature differs from the recomputed MAC', () => with_mac((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		let wrong = encoding.b64url_encode('not-the-mac').data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE' }), jws.verify(native, `${h}.${p}.${wrong}`, SECRET));
	}));

	it('returns INVALID_SIGNATURE when native.hmac_sha256 returns null', () => {
		mock.inject('native', { strict: true, data: { hmac_sha256: null } }, (native) => {
			let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
			let p = encoding.b64url_encode('{}').data;
			assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE' }), jws.verify(native, `${h}.${p}.${MAC_SIG}`, SECRET));
		});
	});

	it('returns INVALID_PAYLOAD_ENCODING for a payload that is not valid base64url (after signature passes)', () => with_mac((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let bad_p = '!!!';
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_ENCODING' }), jws.verify(native, `${h}.${bad_p}.${MAC_SIG}`, SECRET));
	}));

	it('returns INVALID_PAYLOAD_JSON for a payload that decodes but is not valid JSON', () => with_mac((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'HS256', typ: 'JWT' })).data;
		let bad_p = encoding.b64url_encode('not-json').data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_JSON' }), jws.verify(native, `${h}.${bad_p}.${MAC_SIG}`, SECRET));
	}));
});

// ─── sign → verify roundtrip ─────────────────────────────────────────────────

describe('crypto.jws: sign/verify roundtrip', () => {
	it('roundtrip restores the original payload', () => with_mac((native) => {
		let payload = { sub: 'user-1', exp: 9999999999, custom: 'value' };
		let token = jws.sign(native, payload, SECRET);
		assert.match(contains({ ok: true }), token);
		assert.match(
			contains({ ok: true, data: contains({ sub: payload.sub, exp: payload.exp, custom: payload.custom }) }),
			jws.verify(native, token.data, SECRET)
		);
	}));

	prop('roundtrip holds for any object payload',
		gen.record({
			sub:   gen.alphanumeric({ min_len: 1, max_len: 20 }),
			value: gen.int(0, 1000000),
		}),
		(payload, ctx) => {
			ctx.classify('large value (>500k)', payload.value > 500000);
			with_mac((native) => {
				let signed = jws.sign(native, payload, SECRET);
				assert.match(contains({ ok: true }), signed);
				assert.match(
					contains({ ok: true, data: contains({ sub: payload.sub, value: payload.value }) }),
					jws.verify(native, signed.data, SECRET)
				);
			});
		}
	);
});
