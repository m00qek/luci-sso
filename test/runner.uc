import { run_all, clear_tests } from 'testing';
import * as fs from 'fs';

// --- Multi-Module Mode ---
let modules_str = getenv("MODULES");
if (modules_str) {
	let modules_list = split(modules_str, " ");
	for (let mod in modules_list) {
		if (length(mod) > 0) {
			require(mod);
		}
	}
	run_all("Targeted Modules: " + modules_str);
	exit(0);
}

// --- Tier 0: Backend Compliance ---
const backend_files = [
	"unit.native_compliance_test",
	"unit.native_torture_test",
	"unit.native_hardening_test"
];

for (let mod in backend_files) {
	require(mod);
}
run_all("Backend Compliance (Tier 0)");

// --- Tier 1: Cryptographic Plumbing ---
clear_tests();
const plumbing_files = [
	"unit.crypto_plumbing_test",
	"unit.crypto_constant_time_test",
	"unit.encoding_security_test"
];

for (let mod in plumbing_files) {
	require(mod);
}
run_all("Plumbing (Tier 1)");

// --- Tier 2: Business Logic ---
clear_tests();
const logic_files = [
	"unit.oidc_logic_test",
	"unit.oidc_security_test",
	"unit.handshake_rotation_test",
	"unit.handshake_warning_test",
	"unit.session_logic_test",
	"unit.session_race_test",
	"unit.ubus_logic_test",
	"unit.config_logic_test",
	"unit.config_scope_test",
	"unit.web_logic_test",
	"unit.security_logic_test",
	"unit.security_logic_test_extra",
	"unit.logout_security_test",
	"unit.fuzz_logic_test",
	"unit.https_enforcement_test",
	"unit.dos_security_test"
];

for (let mod in logic_files) {
	require(mod);
}
run_all("Business Logic (Tier 2)");

// --- Tier 3: Behavioral Integration ---
clear_tests();
const integration_files = [
	"integration.router_test"
];

for (let mod in integration_files) {
	require(mod);
}
run_all("Integration Tests (Tier 3)");

// --- Tier 4: Meta (Test Harness) ---
clear_tests();
require("meta.mock_test");
run_all("Meta Tests (Tier 4)");