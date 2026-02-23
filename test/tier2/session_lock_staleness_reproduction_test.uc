import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: get_secret_key - reproduction of permanent lockout on stale lock', () => {
    let factory = mock.create();
    const lock_path = "/etc/luci-sso/secret.key.lock";

    // 1. Simulate a stale lock from a previous crashed process
    // We create the directory manually and set its mtime to way in the past.
    // In mock, stat() returns { mtime: state.now }.
    
    factory.with_files({
        [lock_path]: { ".type": "directory" }
    }).spy((io) => {
        // Force the mock to report a very old mtime for the lock
        let original_stat = io.stat;
        io.stat = (path) => {
            if (path == lock_path) return { mtime: 1000000000 }; // Very old
            return original_stat(path);
        };

        let res = session.get_secret_key(io);
        
        assert(res.ok, "Should succeed with self-healing");
        assert_eq(length(res.data), 32, "Should return a 32-byte key");

        let history = mock.create().using(io).spy((dummy) => {}); // Get history from IO
        // Wait, 'io' is the one that has the history.
        // Let's use the spy handle from factory.spy().
    });
});

test('session: get_secret_key - self-healing log and cleanup verification', () => {
    let factory = mock.create();
    const lock_path = "/etc/luci-sso/secret.key.lock";

    let history = factory.with_files({
        [lock_path]: { ".type": "directory" }
    }).spy((io) => {
        let original_stat = io.stat;
        io.stat = (path) => {
            if (path == lock_path) return { mtime: 1000000000 };
            return original_stat(path);
        };
        session.get_secret_key(io);
    });

    assert(history.called("log", "warn", "Stale secret key lock detected; performing self-healing cleanup"), "Should log self-healing event");
    assert(history.called("remove", lock_path), "Should remove the stale lock");
    assert(history.called("write_file", "/etc/luci-sso/secret.key.tmp"), "Should proceed with generation after healing");
});

