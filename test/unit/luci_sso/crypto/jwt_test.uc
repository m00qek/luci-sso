import { describe, it, prop, gen, assert, contains, mock, spy } from 'utest';
import * as jwt from 'luci_sso.crypto.jwt';
import * as encoding from 'luci_sso.encoding';

// jwt.verify fakes `native` (data-first) so these tests exercise only the
// wrapper: contract guards, structural parsing, the alg → verify_rs256/es256
// dispatch, and the claims-validation state machine. Real RS256/ES256
// signature checking lives in test/native.

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

// A signature that native accepts (both algs) — for claims/dispatch tests.
function with_pass(fn) {
	mock.inject('native', { strict: true, data: { verify_rs256: true, verify_es256: true } }, fn);
}

// A signature that native rejects.
function with_fail(fn) {
	mock.inject('native', { strict: true, data: { verify_rs256: false, verify_es256: false } }, fn);
}

// native must never be called — any call dies (strict, no data).
function with_strict(fn) {
	mock.inject('native', { strict: true }, fn);
}

// ─── contract violations ──────────────────────────────────────────────────────

describe('crypto.jwt: verify — contract', () => {
	const opts = BASE_OPTS;

	it('dies when token is not a string', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, null, 'pem', opts), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(native, 42,   'pem', opts), /CONTRACT_VIOLATION/);
	}));

	it('dies when pubkey is not a string', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', null, opts), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(native, 'tok', 42,   opts), /CONTRACT_VIOLATION/);
	}));

	it('dies when options is not an object', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', 'pem', null), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(native, 'tok', 'pem', 'str'), /CONTRACT_VIOLATION/);
	}));

	it('dies when options.now is not an integer', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', 'pem', { ...opts, now: '1700000000' }), /CONTRACT_VIOLATION/);
		assert.throws(() => jwt.verify(native, 'tok', 'pem', { ...opts, now: null }), /CONTRACT_VIOLATION/);
	}));

	it('dies when options.clock_tolerance is not an integer', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', 'pem', { ...opts, clock_tolerance: '0' }), /CONTRACT_VIOLATION/);
	}));

	it('dies when options.iss is not a string', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', 'pem', { ...opts, iss: null }), /CONTRACT_VIOLATION/);
	}));

	it('dies when options.aud is not a string', () => with_strict((native) => {
		assert.throws(() => jwt.verify(native, 'tok', 'pem', { ...opts, aud: null }), /CONTRACT_VIOLATION/);
	}));
});

// ─── structural validation ────────────────────────────────────────────────────
// Every case here returns before the signature step, so native is never called.

describe('crypto.jwt: verify — structural', () => {
	it('returns TOKEN_TOO_LARGE for tokens exceeding 16 KB', () => with_strict((native) => {
		let huge = '';
		for (let i = 0; i < 16385; i++) huge += 'a';
		assert.match(contains({ ok: false, error: 'TOKEN_TOO_LARGE' }), jwt.verify(native, huge, 'pem', BASE_OPTS));
	}));

	it('returns MISSING_ALGORITHM_OPTION when alg is absent', () => with_strict((native) => {
		let opts = { ...BASE_OPTS };
		delete opts.alg;
		assert.match(contains({ ok: false, error: 'MISSING_ALGORITHM_OPTION' }), jwt.verify(native, 'a.b.c', 'pem', opts));
	}));

	it('returns MALFORMED_JWT for tokens with fewer than 3 parts', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MALFORMED_JWT' }), jwt.verify(native, 'only.two', 'pem', BASE_OPTS));
	}));

	it('returns MALFORMED_JWT for tokens with more than 3 parts', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MALFORMED_JWT' }), jwt.verify(native, 'a.b.c.d', 'pem', BASE_OPTS));
	}));

	it('returns INVALID_HEADER_ENCODING for a non-base64url header', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_ENCODING' }), jwt.verify(native, '!!!!.payload.sig', 'pem', BASE_OPTS));
	}));

	it('returns INVALID_HEADER_JSON when header decodes but is not valid JSON', () => with_strict((native) => {
		let h = encoding.b64url_encode('not-json').data;
		assert.match(contains({ ok: false, error: 'INVALID_HEADER_JSON' }), jwt.verify(native, `${h}.payload.sig`, 'pem', BASE_OPTS));
	}));

	it('returns ALGORITHM_MISMATCH when header alg differs from options.alg', () => with_strict((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'ES256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('{}').data;
		assert.match(contains({ ok: false, error: 'ALGORITHM_MISMATCH' }), jwt.verify(native, `${h}.${p}.AAAA`, 'pem', BASE_OPTS));
	}));

	it('returns UNSUPPORTED_ALGORITHM for unsupported alg in options', () => with_strict((native) => {
		let opts = { ...BASE_OPTS, alg: 'HS256' };
		assert.match(contains({ ok: false, error: 'UNSUPPORTED_ALGORITHM' }), jwt.verify(native, make_jwt({ alg: 'HS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts));
	}));

	it('returns INVALID_PAYLOAD_ENCODING for a non-base64url payload', () => with_strict((native) => {
		// payload decode is a fail-fast step that runs before signature verification
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_ENCODING' }), jwt.verify(native, `${h}.!!!!.sig`, 'pem', BASE_OPTS));
	}));

	it('returns INVALID_SIGNATURE_ENCODING for a non-base64url signature', () => with_strict((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode(sprintf('%J', VALID_PAYLOAD)).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jwt.verify(native, `${h}.${p}.!!!!`, 'pem', BASE_OPTS));
	}));

	it('returns INVALID_SIGNATURE_ENCODING for a zero-length decoded signature', () => with_strict((native) => {
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode(sprintf('%J', VALID_PAYLOAD)).data;
		assert.match(contains({ ok: false, error: 'INVALID_SIGNATURE_ENCODING' }), jwt.verify(native, `${h}.${p}.`, 'pem', BASE_OPTS));
	}));

	it('returns INVALID_PAYLOAD_JSON when payload decodes but is not valid JSON', () => with_pass((native) => {
		// payload JSON parse runs after signature verification — pass the signature to reach it
		let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
		let p = encoding.b64url_encode('not-json').data;
		assert.match(contains({ ok: false, error: 'INVALID_PAYLOAD_JSON' }), jwt.verify(native, `${h}.${p}.AAAA`, 'pem', BASE_OPTS));
	}));
});

// ─── signature dispatch ───────────────────────────────────────────────────────

describe('crypto.jwt: verify — signature', () => {
	it('forwards signed_data, decoded signature, and pubkey to verify_rs256', () => {
		mock.inject('native', { strict: true, data: { verify_rs256: true } }, (native) => {
			let payload = { ...VALID_PAYLOAD };
			delete payload.exp; // stop right after the signature check, at MISSING_EXP_CLAIM
			let h = encoding.b64url_encode(sprintf('%J', { alg: 'RS256', typ: 'JWT' })).data;
			let p = encoding.b64url_encode(sprintf('%J', payload)).data;
			let sig = encoding.b64url_encode('raw-signature-bytes').data;

			let res = jwt.verify(native, `${h}.${p}.${sig}`, 'the-pem', BASE_OPTS);
			assert.match(contains({ ok: false, error: 'MISSING_EXP_CLAIM' }), res);

			let call = spy(native).calls.verify_rs256[0];
			assert.match(`${h}.${p}`, call[0]);
			assert.match('raw-signature-bytes', call[1]);
			assert.match('the-pem', call[2]);
		});
	});

	it('returns INVALID_SIGNATURE when native rejects the signature', () => with_fail((native) => {
		assert.match(
			contains({ ok: false, error: 'INVALID_SIGNATURE' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', BASE_OPTS)
		);
	}));
});

// ─── claims validation ────────────────────────────────────────────────────────

describe('crypto.jwt: verify — claims', () => {
	it('accepts a fully valid JWT', () => with_pass((native) => {
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', BASE_OPTS)
		);
	}));

	it('returns MISSING_EXP_CLAIM when exp is absent', () => with_pass((native) => {
		let payload = { ...VALID_PAYLOAD };
		delete payload.exp;
		assert.match(
			contains({ ok: false, error: 'MISSING_EXP_CLAIM' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS)
		);
	}));

	it('returns MISSING_IAT_CLAIM when iat is absent', () => with_pass((native) => {
		let payload = { ...VALID_PAYLOAD };
		delete payload.iat;
		assert.match(
			contains({ ok: false, error: 'MISSING_IAT_CLAIM' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS)
		);
	}));

	it('returns INVALID_EXP_CLAIM when exp is present but not an integer', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'INVALID_EXP_CLAIM' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: '1700000000' }), 'pem', BASE_OPTS)
		);
	}));

	it('returns INVALID_IAT_CLAIM when iat is present but not an integer', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'INVALID_IAT_CLAIM' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iat: '1516239022' }), 'pem', BASE_OPTS)
		);
	}));

	it('returns INVALID_NBF_CLAIM when nbf is present but not an integer', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'INVALID_NBF_CLAIM' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: 'not-a-number' }), 'pem', BASE_OPTS)
		);
	}));

	it('returns TOKEN_EXPIRED when exp is in the past', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_EXPIRED' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 1 }), 'pem', BASE_OPTS)
		);
	}));

	it('accepts a recently expired token within clock_tolerance', () => with_pass((native) => {
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: true }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 30 }), 'pem', opts)
		);
	}));

	it('accepts a token exactly at the expiry+tolerance boundary (exp == now - tolerance)', () => with_pass((native) => {
		// code is: if (exp < now - tolerance) reject — equality passes
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: true }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 60 }), 'pem', opts)
		);
	}));

	it('rejects an expired token beyond clock_tolerance', () => with_pass((native) => {
		let opts = { ...BASE_OPTS, clock_tolerance: 60 };
		assert.match(
			contains({ ok: false, error: 'TOKEN_EXPIRED' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, exp: NOW - 120 }), 'pem', opts)
		);
	}));

	it('returns TOKEN_ISSUED_IN_FUTURE when iat is in the future', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_ISSUED_IN_FUTURE' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iat: NOW + 1000 }), 'pem', BASE_OPTS)
		);
	}));

	it('returns TOKEN_NOT_YET_VALID when nbf is in the future', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'TOKEN_NOT_YET_VALID' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: NOW + 500 }), 'pem', BASE_OPTS)
		);
	}));

	it('accepts nbf in the past', () => with_pass((native) => {
		assert.match(
			contains({ ok: true }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, nbf: NOW - 60 }), 'pem', BASE_OPTS)
		);
	}));

	it('returns ISSUER_MISMATCH when iss does not match', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'ISSUER_MISMATCH' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iss: 'https://different.example.com' }), 'pem', BASE_OPTS)
		);
	}));

	it('returns ISSUER_MISMATCH for an iss that differs only by normalization (OIDC Core §3.1.3.7 (2))', () => with_pass((native) => {
		// iss must be the exact issuer identifier: no trailing-slash, case or port folding.
		for (let iss in [ 'https://issuer.example.com/', 'HTTPS://ISSUER.EXAMPLE.COM', 'https://Issuer.example.com', 'https://issuer.example.com:443' ]) {
			assert.match(
				contains({ ok: false, error: 'ISSUER_MISMATCH' }),
				jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, iss }), 'pem', BASE_OPTS),
				iss
			);
		}
	}));

	it('returns ISSUER_MISMATCH for a missing or non-string iss', () => with_pass((native) => {
		for (let iss in [ null, 42, [ BASE_OPTS.iss ], { v: BASE_OPTS.iss } ]) {
			let payload = { ...VALID_PAYLOAD, iss };
			if (iss == null) delete payload.iss;
			assert.match(
				contains({ ok: false, error: 'ISSUER_MISMATCH' }),
				jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS),
				sprintf('%J', iss)
			);
		}
	}));

	it('returns AUDIENCE_MISMATCH when aud string does not match', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: 'different-client' }), 'pem', BASE_OPTS)
		);
	}));

	it('accepts aud as the string client_id (Keycloak, Authentik)', () => with_pass((native) => {
		assert.match(
			contains({ ok: true }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: 'test-client' }), 'pem', BASE_OPTS)
		);
	}));

	it('accepts aud as the one-entry array [client_id] (Pocket ID, Authelia)', () => with_pass((native) => {
		assert.match(
			contains({ ok: true }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: ['test-client'] }), 'pem', BASE_OPTS)
		);
	}));

	it('returns AUDIENCE_MISMATCH when aud lists an additional untrusted audience (OIDC Core §3.1.3.7 (3))', () => with_pass((native) => {
		for (let aud in [ ['other-client', 'test-client', 'yet-another'], ['test-client', 'other'], ['other', 'test-client'], ['test-client', 'test-client'] ]) {
			assert.match(
				contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
				jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud }), 'pem', BASE_OPTS),
				sprintf('%J', aud)
			);
		}
	}));

	it('returns AUDIENCE_MISMATCH when aud is missing or neither a string nor an array', () => with_pass((native) => {
		for (let aud in [ null, 42, true, { 'test-client': true } ]) {
			let payload = { ...VALID_PAYLOAD, aud };
			if (aud == null) delete payload.aud;
			assert.match(
				contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
				jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS),
				sprintf('%J', aud)
			);
		}
	}));

	it('returns AUDIENCE_MISMATCH when aud array does not contain the expected client', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'AUDIENCE_MISMATCH' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: ['client-a', 'client-b'] }), 'pem', BASE_OPTS)
		);
	}));

	it('returns INVALID_AUDIENCE for an empty aud array', () => with_pass((native) => {
		assert.match(
			contains({ ok: false, error: 'INVALID_AUDIENCE' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud: [] }), 'pem', BASE_OPTS)
		);
	}));

	it('returns MALFORMED_AUDIENCE when any aud array entry is not a string, before or after the match', () => with_pass((native) => {
		for (let aud in [ [42, 'test-client'], ['test-client', 42], ['test-client', null], ['test-client', ['x']], [{}] ]) {
			assert.match(
				contains({ ok: false, error: 'MALFORMED_AUDIENCE' }),
				jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, { ...VALID_PAYLOAD, aud }), 'pem', BASE_OPTS),
				sprintf('%J', aud)
			);
		}
	}));
});

// ─── ES256 algorithm path ─────────────────────────────────────────────────────

describe('crypto.jwt: verify — ES256', () => {
	it('accepts a valid ES256 JWT', () => with_pass((native) => {
		let es_opts = { ...BASE_OPTS, alg: 'ES256' };
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(native, make_jwt({ alg: 'ES256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', es_opts)
		);
	}));

	it('dispatches to verify_es256 for the ES256 algorithm', () => {
		mock.inject('native', { strict: true, data: { verify_es256: true } }, (native) => {
			let es_opts = { ...BASE_OPTS, alg: 'ES256' };
			jwt.verify(native, make_jwt({ alg: 'ES256', typ: 'JWT' }, VALID_PAYLOAD), 'ec-pem', es_opts);
			assert.match('ec-pem', spy(native).calls.verify_es256[0][2]);
		});
	});

	it('returns INVALID_SIGNATURE when verify_es256 rejects the signature', () => with_fail((native) => {
		let es_opts = { ...BASE_OPTS, alg: 'ES256' };
		assert.match(
			contains({ ok: false, error: 'INVALID_SIGNATURE' }),
			jwt.verify(native, make_jwt({ alg: 'ES256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', es_opts)
		);
	}));
});

// ─── pre_parsed_header fast path ──────────────────────────────────────────────

describe('crypto.jwt: verify — pre_parsed_header', () => {
	it('uses pre_parsed_header to skip header decode', () => with_pass((native) => {
		let opts = { ...BASE_OPTS, pre_parsed_header: { alg: 'RS256', typ: 'JWT' } };
		assert.match(
			contains({ ok: true, data: contains({ sub: VALID_PAYLOAD.sub }) }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts)
		);
	}));

	it('returns ALGORITHM_MISMATCH when pre_parsed_header.alg differs from options.alg', () => with_strict((native) => {
		let opts = { ...BASE_OPTS, pre_parsed_header: { alg: 'ES256', typ: 'JWT' } };
		assert.match(
			contains({ ok: false, error: 'ALGORITHM_MISMATCH' }),
			jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, VALID_PAYLOAD), 'pem', opts)
		);
	}));
});

// ─── claims validation (properties) ───────────────────────────────────────────
// The time-window state machine, exhaustively probed. Signature is faked-accept
// (with_pass), so the outcome is a pure function of (claim, now, clock_tolerance).

// The audience pool includes the expected client so membership varies naturally.
const AUD_POOL = ['alpha-client', BASE_OPTS.aud, 'beta-client', 'gamma-client'];

describe('crypto.jwt: verify — claims (properties)', () => {
	prop('exp is accepted iff exp >= now - clock_tolerance (else TOKEN_EXPIRED)',
		gen.tuple(gen.int(0, 300), gen.int(-600, 600)),
		(t, ctx) => {
			let tol = t[0], delta = t[1];
			let opts = { ...BASE_OPTS, clock_tolerance: tol };
			// iat safely in the past so only the exp branch decides the outcome.
			let payload = { ...VALID_PAYLOAD, iat: NOW - 1000, exp: NOW + delta };
			let expect_ok = (NOW + delta) >= (NOW - tol);
			ctx.classify('accepted', expect_ok);
			ctx.classify('at boundary', delta === -tol);
			with_pass((native) => {
				let res = jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', opts);
				assert.match(expect_ok ? contains({ ok: true }) : contains({ ok: false, error: 'TOKEN_EXPIRED' }), res);
			});
		}
	);

	prop('iat is accepted iff iat <= now + clock_tolerance (else TOKEN_ISSUED_IN_FUTURE)',
		gen.tuple(gen.int(0, 300), gen.int(-600, 600)),
		(t, ctx) => {
			let tol = t[0], delta = t[1];
			let opts = { ...BASE_OPTS, clock_tolerance: tol };
			// exp safely in the future so only the iat branch decides the outcome.
			let payload = { ...VALID_PAYLOAD, exp: NOW + 10000, iat: NOW + delta };
			let expect_ok = (NOW + delta) <= (NOW + tol);
			ctx.classify('accepted', expect_ok);
			ctx.classify('at boundary', delta === tol);
			with_pass((native) => {
				let res = jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', opts);
				assert.match(expect_ok ? contains({ ok: true }) : contains({ ok: false, error: 'TOKEN_ISSUED_IN_FUTURE' }), res);
			});
		}
	);

	prop('nbf (when present) is accepted iff nbf <= now + clock_tolerance (else TOKEN_NOT_YET_VALID)',
		gen.tuple(gen.int(0, 300), gen.int(-600, 600)),
		(t, ctx) => {
			let tol = t[0], delta = t[1];
			let opts = { ...BASE_OPTS, clock_tolerance: tol };
			let payload = { ...VALID_PAYLOAD, nbf: NOW + delta };
			let expect_ok = (NOW + delta) <= (NOW + tol);
			ctx.classify('not yet valid', !expect_ok);
			with_pass((native) => {
				let res = jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', opts);
				assert.match(expect_ok ? contains({ ok: true }) : contains({ ok: false, error: 'TOKEN_NOT_YET_VALID' }), res);
			});
		}
	);

	prop('an aud array is accepted iff it is exactly [client_id]',
		gen.map(gen.array(gen.int(0, 3), { min_len: 0, max_len: 5 }),
		        (idxs) => map(idxs, (i) => AUD_POOL[i])),
		(auds, ctx) => {
			let exact = (length(auds) === 1 && auds[0] === BASE_OPTS.aud);
			let has_client = false;
			for (let a in auds) if (a === BASE_OPTS.aud) has_client = true;
			ctx.classify('empty', length(auds) === 0);
			ctx.classify('exactly [client_id]', exact);
			ctx.classify('client plus others', has_client && !exact);
			let payload = { ...VALID_PAYLOAD, aud: auds };
			with_pass((native) => {
				let res = jwt.verify(native, make_jwt({ alg: 'RS256', typ: 'JWT' }, payload), 'pem', BASE_OPTS);
				if (length(auds) === 0)
					assert.match(contains({ ok: false, error: 'INVALID_AUDIENCE' }), res);
				else if (exact)
					assert.match(contains({ ok: true }), res);
				else
					assert.match(contains({ ok: false, error: 'AUDIENCE_MISMATCH' }), res);
			});
		}
	);
});
