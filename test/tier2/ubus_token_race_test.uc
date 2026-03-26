import { test, assert, assert_eq } from 'testing';
import * as ubus from 'luci_sso.ubus';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Token Registry Race Condition & Persistence
// =============================================================================

test('ubus: register_token - handles concurrent registration (replay)', () => {
    let factory = mock.create();
    let token = "some-access-token-12345";
    
    factory.with_env({}, (io) => {
        // 1. First registration succeeds
        io.mkdir = (path, mode) => true; 
        let res1 = ubus.register_token(io, token);
        assert(res1.ok, "First registration should succeed");

        // 2. Second registration (Simulated Replay/Race)
        // If mkdir returns false, it means the directory (lock) already exists.
        io.mkdir = (path, mode) => {
            // We ignore the registry dir creation but fail the token-specific lock
            if (match(path, /tokens$/)) return true;
            return false; 
        };
        
        let res2 = ubus.register_token(io, token);
        assert(!res2.ok, "Second registration MUST fail");
        assert_eq(res2.error, "TOKEN_REPLAYED");
    });
});

test('ubus: register_token - resilience to registry mkdir failure', () => {
    let factory = mock.create();
    let token = "token-123";
    
    factory.with_env({}, (io) => {
        // Mock a scenario where the base tokens/ directory cannot be created 
        // BUT it doesn't exist yet (e.g. permission error).
        // However, in our implementation, we ignore mkdir errors for the base dir.
        // What matters is the lock_path creation.
        
        io.mkdir = (path, mode) => {
            if (match(path, /tokens$/)) return false; // Fail base dir
            return true; // Succeed for the token lock itself (shouldn't happen if base fails, but testing logic)
        };
        
        let res = ubus.register_token(io, token);
        assert(res.ok, "Should proceed if token lock succeeds despite base dir mkdir returning false (might already exist)");
    });
});
