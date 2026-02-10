import { test, assert, assert_eq } from '../testing.uc';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('Session: Race Condition - Should fail instead of falling back to random key when lock is held', () => {
    const lock_path = "/etc/luci-sso/secret.key.lock";
    mock.create()
        .with_files({
            // Path exists but is empty (simulating partial write or race)
            "/etc/luci-sso/secret.key": "",
            // PRE-EXISTING LOCK DIRECTORY (mkdir will return false)
            [lock_path]: { ".type": "directory" }
        })
        .with_env({}, (io) => {
            let res = session.get_secret_key(io);
            
            // In the current buggy version, it falls back and returns ok: true
            assert(!res.ok, "Should NOT return ok if key is missing and lock is held");
            assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
        });
});