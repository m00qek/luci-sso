import { test, assert, assert_eq } from 'testing';
import * as ubus from 'luci_sso.ubus';
import * as mock from 'mock';

test('UBUS: Logic - get_session success', () => {
	let factory = mock.create().with_ubus({
		"session:get": (args) => {
			assert_eq(args.ubus_rpc_session, "sid-123");
			return { values: { oidc_user: "test@example.com", oidc_id_token: "token-abc" } };
		}
	});

	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, "sid-123");
		assert(res.ok);
		assert_eq(res.data.oidc_user, "test@example.com");
		assert_eq(res.data.oidc_id_token, "token-abc");
	});
});

test('UBUS: Logic - get_session handle missing session', () => {
	let factory = mock.create().with_ubus({
		"session:get": (args) => null
	});

	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, "invalid-sid");
		assert(!res.ok);
		assert_eq(res.error, "SESSION_NOT_FOUND");
	});
});

test('UBUS: Logic - get_session handle invalid SID', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, null);
		assert(!res.ok);
		assert_eq(res.error, "INVALID_SID");
	});
});
