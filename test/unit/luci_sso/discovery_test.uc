import { describe, it, prop, gen, assert, contains } from 'utest';
import * as discovery from 'luci_sso.discovery';

const KEY_RS256 = { kid: 'key-1', kty: 'RSA', alg: 'RS256', use: 'sig' };
const KEY_ES256 = { kid: 'key-2', kty: 'EC',  alg: 'ES256', use: 'sig' };

// ─── find_jwk ────────────────────────────────────────────────────────────────

describe('discovery: find_jwk', () => {
	it('dies with CONTRACT_VIOLATION when keys is not an array', () => {
		assert.throws(() => discovery.find_jwk(null, 'key-1'), /CONTRACT_VIOLATION/);
		assert.throws(() => discovery.find_jwk({},   'key-1'), /CONTRACT_VIOLATION/);
	});

	it('returns NO_KEYS_AVAILABLE when keys is empty and kid is absent', () => {
		assert.match(contains({ ok: false, error: 'NO_KEYS_AVAILABLE' }),
			discovery.find_jwk([], null));
	});

	it('returns the first key when kid is absent and keys is non-empty', () => {
		assert.match(contains({ ok: true, data: KEY_RS256 }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], null));
	});

	it('returns the matching key by kid', () => {
		assert.match(contains({ ok: true, data: KEY_ES256 }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], 'key-2'));
	});

	it('returns KEY_NOT_FOUND when kid does not match any key', () => {
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			discovery.find_jwk([KEY_RS256, KEY_ES256], 'no-such-key'));
	});

	it('returns KEY_NOT_FOUND when keys is empty and kid is specified', () => {
		assert.match(contains({ ok: false, error: 'KEY_NOT_FOUND' }),
			discovery.find_jwk([], 'key-1'));
	});

	// A key in the array is always findable by its own kid.
	prop('find_jwk always finds a key that is present by its kid',
		gen.array(gen.record({ kid: gen.alphanumeric({ min_len: 1, max_len: 10 }) }), { min_len: 1, max_len: 10 }),
		(keys, ctx) => {
			ctx.classify('single key', length(keys) == 1);
			let res = discovery.find_jwk(keys, keys[0].kid);
			assert.match(contains({ ok: true, data: { kid: keys[0].kid } }), res);
		}
	);

	// When no kid is specified, the first element is always returned.
	prop('find_jwk returns the first key when kid is null',
		gen.array(gen.record({ kid: gen.alphanumeric({ min_len: 1, max_len: 10 }) }), { min_len: 1, max_len: 10 }),
		(keys) => {
			assert.match(contains({ ok: true, data: keys[0] }), discovery.find_jwk(keys, null));
		}
	);
});
