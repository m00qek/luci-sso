import { test, assert, assert_eq } from '../testing.uc';
import * as session from 'luci_sso.session';
import * as mock from 'mock';
import * as Result from 'luci_sso.result';

test('session: get_secret_key - handle write failure', () => {
    mock.create()
        .with_files({})
        .spy((io) => {
            // Mock io.write_file to always fail
            io.write_file = () => false;
            
            let res = session.get_secret_key(io);
            
            assert(!res.ok, "get_secret_key should fail when write_file fails");
            assert_eq(res.error, "SYSTEM_KEY_WRITE_FAILED");
            
            // Ensure lock is removed even on failure
            let stat = io.stat("/etc/luci-sso/secret.key.lock");
            assert(!stat, "Lock directory should be removed after failure");
        });
});
