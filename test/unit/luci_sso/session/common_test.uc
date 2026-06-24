import { describe, it, assert, mock } from 'utest';
import * as common from 'luci_sso.session.common';

// ─── constants ───────────────────────────────────────────────────────────────

describe('session.common: constants', () => {
	it('SECRET_KEY_PATH', () => {
		assert.match('/etc/luci-sso/secret.key', common.SECRET_KEY_PATH);
	});

	it('SESSION_DURATION', () => {
		assert.match(3600, common.SESSION_DURATION);
	});

	it('HANDSHAKE_DURATION', () => {
		assert.match(300, common.HANDSHAKE_DURATION);
	});

	it('HANDSHAKE_DIR', () => {
		assert.match('/var/run/luci-sso', common.HANDSHAKE_DIR);
	});

	it('REAP_GRACE_PERIOD', () => {
		assert.match(60, common.REAP_GRACE_PERIOD);
	});

	it('HANDSHAKE_MAX_COUNT', () => {
		assert.match(100, common.HANDSHAKE_MAX_COUNT);
	});
});

// ─── ensure_handshake_dir ────────────────────────────────────────────────────

describe('session.common: ensure_handshake_dir', () => {
	it('calls mkdir with HANDSHAKE_DIR', () => {
		mock.inject_all({ fs: {} }, (injected) => {
			common.ensure_handshake_dir({ fs: injected.fs });
			assert.match(common.HANDSHAKE_DIR, injected.fs.__utest__.calls.mkdir[0][0]);
		});
	});

	it('does not throw when mkdir throws', () => {
		mock.inject_all({ fs: { behavior: { mkdir: () => { die('EPERM'); } } } }, (injected) => {
			common.ensure_handshake_dir({ fs: injected.fs });
		});
	});
});
