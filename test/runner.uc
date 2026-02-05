import { run_all, clear_tests } from 'testing';
import * as fs from 'fs';

// 1. Run Unit Tests first
const unit_files = [
	"unit.crypto_fuzz_test",
	"unit.crypto_native_test",
	"unit.crypto_test",
	"unit.oidc_test",
	"unit.security_test",
	"unit.session_test",
	"unit.utils_test",
	"unit.config_test"
];

for (let mod in unit_files) {
	require(mod);
}
run_all("Unit Tests");

// 2. Clear state and Run Integration Tests (Behavioral Specifications)
clear_tests();
const integration_files = [
	"integration.router_test"
];

for (let mod in integration_files) {
	require(mod);
}
run_all("Integration Tests");
