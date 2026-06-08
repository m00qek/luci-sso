import { it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import * as mock from 'mock';
import * as Result from 'luci_sso.result';

it('session: get_secret_key - handle write failure', () => {
    mock.create()
        .with_files({})
        .spy((io) => {
            // Mock io.write_file to always fail
            io.write_file = () => false;
            
            let res = session.get_secret_key(io);
            
            assert.match(truthy(), !res.ok, "get_secret_key should fail when write_file fails");
            assert.match("SYSTEM_KEY_WRITE_FAILED", res.error);
            
            // Ensure lock is removed even on failure
            let stat = io.stat("/etc/luci-sso/secret.key.lock");
            assert.match(truthy(), !stat, "Lock directory should be removed after failure");
        });
});
