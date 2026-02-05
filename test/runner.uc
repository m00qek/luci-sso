import { run_all } from 'testing';

const test_files = [
	"unit.crypto_fuzz_test",
	"unit.crypto_native_test",
	"unit.crypto_test",
	"unit.oidc_test",
	"unit.security_test",
	"unit.session_test",
	"integration.router_test"
];

for (let mod in test_files) {
	try {
		require(mod);
	} catch (e) {
		die(`Failed to load test module '${mod}': ${e}\n`);
	}
}

run_all();
