import { describe, it, assert, equals, contains } from 'utest';
import * as real_native from 'luci_sso.native';
import * as jwt from 'luci_sso.crypto.jwt';
import * as encoding from 'luci_sso.encoding';
import { PLUMBING_RSA } from 'tier1.fixtures';

// pass_native accepts any signature — allows testing claims validation in isolation
const pass_native = {
	verify_rs256: () => true,
	verify_es256: () => true,
};

const fail_native = {
	verify_rs256: () => false,
	verify_es256: () => false,
};

const NOW = 1700000000;

const BASE_OPTS = {
	alg:             'RS256',
	iss:             'https://issuer.example.com',
	aud:             'test-client',
	now:             NOW,
	clock_tolerance: 0,
};

// Payload that satisfies all claim constraints
const VALID_PAYLOAD = {
	sub: 'user-1',
	iss: 'https://issuer.example.com',
	aud: 'test-client',
	iat: NOW - 60,
	exp: NOW + 3600,
};

function make_jwt(header, payload) {
	let h = encoding.b64url_encode(sprintf('%J', header)).data;
	let p = encoding.b64url_encode(sprintf('%J', payload)).data;
	return `${h}.${p}.AAAA`;
}

// ─── contract violations ──────────────────────────────────────────────────────

describe('crypto.jwt: verify — contract', () => {
	const opts = BASE_OPTS;

	it('dies when token is not a string', () => {
		assert.throws(() => jwt.verify(real_native, null, 'pem', opts), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(real_native, 42,   'pem', opts), /CONTRACT_VIOLATION/);
	});

	it('dies when pubkey is not a string', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', null, opts), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(real_native, 'tok', 42,   opts), /CONTRACT_VIOLATION/);
	});

	it('dies when options is not an object', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', null), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', 'str'), /CONTRACT_VIOLATION/);
	});

	it('dies when options.now is not an integer', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', { ...opts, now: '1700000000' }), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', { ...opts, now: null }), /CONTRACT_VIOLATION/);
	});

	it('dies when options.clock_tolerance is not an integer', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', { ...opts, clock_tolerance: '0' }), /CONTRACT_VIOLATION/);
	});

	it('dies when options.iss is not a string', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', { ...opts, iss: null }), /CONTRACT_VIOLATION/);
	});

	it('dies when options.aud is not a string', () => {
		assert.throws(() => jwt.verify(real_native, 'tok', 'pem', { ...opts, aud: null }), /CONTRACT_VIOLATION/);
	});
});

// ─── structural validation ────────────────────────────────────────────────────

describe('crypto.jwt: verify — structural', () => {
	it('returns TOKEN_TOO_LARGE for tokens exceeding 16 KB', () => {
		let huge = '';
		for (let i = 0; i < 16385; i++) huge += 'a';
		assert.match(contains({ ok: false, error: 'TOKEN_TOO_LARGE' }), jwt.verify(real_native, huge, 'pem', BASE_OPTS));
	});

	it('returns MISSING_ALGORITHM_OPTION when alg is absent', () => {
		let opts = { ...BASE_OPTS };
		delete opts.alg;
		assert.match(contains({ ok: false, error: 'MISSING_ALGORITHM_OPTION' }), jwt.verify(real_native, 'a.b.c', 'pem', opts));
	});

	it('returns MALFORMED_JWT for tokens with fewer than 3 parts', () => {
		assert.match(contains({ ok: false, error: 'MALFORMED_JWT' }), jwt.verify(real_native, 'only.two', 'pem', BASE_OPTS));
	});

	it('returns MALFORMED_JWT for tokens with more than 3 parts', () => {
		assert.match(contains({ ok: false, error: 'MALFORMED_JWT' }), jwt.verify(real_native, 'a.b.c.d', 'pem', BASE_OPTS));
	});

	it('returns INVALID_HEADER_ENCODING for a non-base64url header', () => {
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_ENCODING' }), jwt.verify(real_native, '!!!!.payload.sig', 'pem', BASE_OPTS));
	});

	it('returns INVALID_HEADER_JSON when header decodes but is not valid JSON', () => {
		let h = encoding.b64url_encode('not-json').data;
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_JSON' }), jwt.verify(real_native, `${h}.payload.sig`, 'pem', BASE_OPTS));
	});

	it('returns ALGORITHM_MISMATCH when header alg differs from options.alg', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'ES256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		assert.match(contains({ ok: false, error: 'ALGORITHM_MISMATCH' }), jwt.verify(real_native, `${h}.${p}.AAAA`, 'pem', BASE_OPTS));
	});

	it('returns UNSUPPORTED_ALGORITHM for unsupported alg in options', () => {
		let opts = { ...BASE_OPTS, alg: 'HS256' };
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }), jwt.verify(real_native, make_jwt({ alg: 'HS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts));
	});

	it('returns INVALID_PAYLOAD_ENCODING for a non-base64url payload', () => {
		// payload decode is a fail-fast step that runs before signature verification
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_ENCODING' }), jwt.verify(real_native, `${h}.!!!!.sig`, 'pem', BASE_OPTS));
	});

	it('returns INVALID_SIGNATURE_ENCODING for a non-base64url signature', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode(sprintf('%J', VALID_PAYLOAD)).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jwt.verify(real_native, `${h}.${p}.!!!!`, 'pem', BASE_OPTS));
	});

	it('returns INVALID_SIGNATURE_ENCODING for a zero-length decoded signature', () => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode(sprintf('%J', VALID_PAYLOAD)).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jwt.verify(real_native, `${h}.${p}.`, 'pem', BASE_OPTS));
	});

	it('returns INVALID_PAYLOAD_JSON when payload decodes but is not valid JSON', () => {
		// payload JSON parse runs after signature verification — use pass_native to bypass it
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('not-json').data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_JSON' }), jwt.verify(pass_native, `${h}.${p}.AAAA`, 'pem', BASE_OPTS));
	});
});

// ─── signature validation ─────────────────────────────────────────────────────

describe('crypto.jwt: verify — signature', () => {
	it('PLUMBING_RSA: real RS256 signature passes the native verification step', () => {
		// PLUMBING_RSA payload has no exp → reaches MISSING_EXP_CLAIM after signature check
		assert.match(
			contains({ ok: false, error: 'MISSING_EXP_CLAIM' }),
			jwt.verify(real_native, PLUMBING_RSA.token, PLUMBING_RSA.pubkey, BASE_OPTS)
		);
	});

	it('returns INVALID_SIGNATURE when native rejects the signature', () => {
		assert.match(
			contains({ ok: false, error: 'INVALID_SIGNATURE' }),
			jwt.verify(fail_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', BASE_OPTS)
		);
	});

	it('returns INVALID_SIGNATURE for a tampered PLUMBING_RSA payload', () => {
		let parts = split(PLUMBING_RSA.token, '.');
		let new_p = encoding.b64url_encode(sprintf('%J', VALID_PAYLOAD)).data;
		assert.match(
			contains({ ok: false, error: 'INVALID_SIGNATURE' }),
			jwt.verify(real_native, `${parts[0]}.${new_p}.${parts[2]}`, PLUMBING_RSA.pubkey, BASE_OPTS)
		);
	});
});

// ─── claims validation ────────────────────────────────────────────────────────

describe('crypto.jwt: verify — claims', () => {
	it('accepts a fully valid JWT', () => {
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', BASE_OPTS)
		);
	});

	it('returns MISSING_EXP_CLAIM when exp is absent', () => {
		let payload = { ...VALID_PAYLOAD };
		delete payload.exp;
		assert.match(
			contains({ ok: false, error: 'MISSING_EXP_CLAIM' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS)
		);
	});

	it('returns MISSING_IAT_CLAIM when iat is absent', () => {
		let payload = { ...VALID_PAYLOAD };
		delete payload.iat;
		assert.match(
			contains({ ok: false, error: 'MISSING_IAT_CLAIM' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS)
		);
	});

	it('returns INVALID_EXP_CLAIM when exp is present but not an integer', () => {
		assert.match(
			contains({ ok: false, error: 'INVALID_EXP_CLAIM' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: '1700000000' }), 'pem', BASE_OPTS)
		);
	});

	it('returns INVALID_IAT_CLAIM when iat is present but not an integer', () => {
		assert.match(
			contains({ ok: false, error: 'INVALID_IAT_CLAIM' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iat: '1516239022' }), 'pem', BASE_OPTS)
		);
	});

	it('returns INVALID_NBF_CLAIM when nbf is present but not an integer', () => {
		assert.match(
			contains({ ok: false, error: 'INVALID_NBF_CLAIM' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: 'not-a-number' }), 'pem', BASE_OPTS)
		);
	});

	it('returns TOKEN_EXPIRED when exp is in the past', () => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_EXPIRED' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 1 }), 'pem', BASE_OPTS)
		);
	});

	it('accepts a recently expired token within clock_tolerance', () => {
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 30 }), 'pem', opts)
		);
	});

	it('accepts a token exactly at the expiry+tolerance boundary (exp == now - tolerance)', () => {
		// code is: if (exp < now - tolerance) reject — equality passes
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 60 }), 'pem', opts)
		);
	});

	it('rejects an expired token beyond clock_tolerance', () => {
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: false, error: 'TOKEN_EXPIRED' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 120 }), 'pem', opts)
		);
	});

	it('returns TOKEN_ISSUED_IN_FUTURE when iat is in the future', () => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_ISSUED_IN_FUTURE' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iat: NOW + 1000 }), 'pem', BASE_OPTS)
		);
	});

	it('returns TOKEN_NOT_YET_VALID when nbf is in the future', () => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_NOT_YET_VALID' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: NOW + 500 }), 'pem', BASE_OPTS)
		);
	});

	it('accepts nbf in the past', () => {
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: NOW - 60 }), 'pem', BASE_OPTS)
		);
	});

	it('returns ISSUER_MISMATCH when iss does not match', () => {
		assert.match(
			contains({ ok: false, error: 'ISSUER_MISMATCH' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iss: 'https://different.example.com' }), 'pem', BASE_OPTS)
		);
	});

	it('normalizes issuer URLs for comparison (trailing slash)', () => {
		// opts.iss and payload.iss differ only by trailing slash — normalize_url should make them equal
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iss: 'https://issuer.example.com/' }), 'pem', BASE_OPTS)
		);
	});

	it('normalizes issuer scheme and host to lowercase', () => {
		// normalize_url lowercases scheme and host
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iss: 'HTTPS://ISSUER.EXAMPLE.COM' }), 'pem', BASE_OPTS)
		);
	});

	it('returns AUDIENCE_MISMATCH when aud string does not match', () => {
		assert.match(
			contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: 'different-client' }), 'pem', BASE_OPTS)
		);
	});

	it('accepts when aud is an array containing the expected client', () => {
		assert.match(
			contains({ ok: true }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: ['other-client', 'test-client', 'yet-another'] }), 'pem', BASE_OPTS)
		);
	});

	it('returns AUDIENCE_MISMATCH when aud array does not contain the expected client', () => {
		assert.match(
			contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: ['client-a', 'client-b'] }), 'pem', BASE_OPTS)
		);
	});

	it('returns INVALID_AUDIENCE for an empty aud array', () => {
		assert.match(
			contains({ ok: false, error: 'INVALID_AUDIENCE' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: [] }), 'pem', BASE_OPTS)
		);
	});

	it('returns MALFORMED_AUDIENCE when aud array contains a non-string element before the match', () => {
		// non-string before the matching entry — iterator hits it first
		assert.match(
			contains({ ok: false, error: 'MALFORMED_AUDIENCE' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: [42, 'test-client'] }), 'pem', BASE_OPTS)
		);
	});
});

// ─── ES256 algorithm path ─────────────────────────────────────────────────────

describe('crypto.jwt: verify — ES256', () => {
	it('accepts a valid ES256 JWT', () => {
		let es_opts = { ...BASE_OPTS, alg: 'ES256' };
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(pass_native, make_jwt({ alg: 'ES256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', es_opts)
		);
	});

	it('returns INVALID_SIGNATURE when verify_es256 rejects the signature', () => {
		let es_opts = { ...BASE_OPTS, alg: 'ES256' };
		assert.match(
			contains({ ok: false, error: 'INVALID_SIGNATURE' }),
			jwt.verify(fail_native, make_jwt({ alg: 'ES256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', es_opts)
		);
	});
});

// ─── pre_parsed_header fast path ──────────────────────────────────────────────

describe('crypto.jwt: verify — pre_parsed_header', () => {
	it('uses pre_parsed_header to skip header decode', () => {
		let opts = { ...BASE_OPTS, pre_parsed_header: { alg: 'RS256', typ: 'JWT' } };
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts)
		);
	});

	it('returns ALGORITHM_MISMATCH when pre_parsed_header.alg differs from options.alg', () => {
		let opts = { ...BASE_OPTS, pre_parsed_header: { alg: 'ES256', typ: 'JWT' } };
		assert.match(
			contains({ ok: false, error: 'ALGORITHM_MISMATCH' }),
			jwt.verify(pass_native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts)
		);
	});
});
