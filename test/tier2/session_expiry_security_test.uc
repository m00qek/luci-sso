import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: verify_state - rejects handshake with exp=0 as expired', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            data.exp = 0; // Explicitly set to zero
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert(!res.ok, "Should fail verification");
            assert_eq(res.error, "HANDSHAKE_EXPIRED", "Should be rejected as expired even if exp is 0 (truthy guard fix)");
        });
});

test('session: verify_state - rejects handshake with missing exp as corrupted', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            delete data.exp;
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert(!res.ok, "Should fail verification");
            assert_eq(res.error, "STATE_CORRUPTED", "Should be rejected as corrupted if exp is missing");
        });
});

test('session: verify_state - rejects handshake with missing iat as corrupted', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            delete data.iat;
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert(!res.ok, "Should fail verification");
            assert_eq(res.error, "STATE_CORRUPTED", "Should be rejected as corrupted if iat is missing");
        });
});
