import { it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

it('session: verify_state - rejects handshake with exp=0 as expired', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            data.exp = 0; // Explicitly set to zero
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert.match(truthy(), !res.ok, "Should fail verification");
            assert.match("HANDSHAKE_EXPIRED", res.error, "Should be rejected as expired even if exp is 0 (truthy guard fix)");
        });
});

it('session: verify_state - rejects handshake with missing exp as corrupted', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            delete data.exp;
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert.match(truthy(), !res.ok, "Should fail verification");
            assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if exp is missing");
        });
});

it('session: verify_state - rejects handshake with missing iat as corrupted', () => {
    mock.create()
        .spy((io) => {
            let s_res = session.create_state(io);
            let handle = s_res.data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let data = json(io.read_file(path));
            delete data.iat;
            io.write_file(path, sprintf("%J", data));

            let res = session.verify_state(io, handle, 300);
            assert.match(truthy(), !res.ok, "Should fail verification");
            assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if iat is missing");
        });
});
