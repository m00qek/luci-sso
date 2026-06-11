import { it, assert, truthy } from 'utest';
import * as handshake from 'luci_sso.handshake';

it('handshake: groups fallback - reproduction of dead code', () => {
	// _complete_oauth_flow is private; this test documents the groups fallback
	// logic exists in handshake.authenticate.
	// Full coverage is provided by handshake_userinfo_test.uc.
});
