import { run_all, clear_tests } from 'testing';
import * as fs from 'fs';

// --- Tier 0: Backend Compliance ---
const backend_files = [
	"unit.native_compliance_test",
	"unit.native_torture_test"
];

for (let mod in backend_files) {
	require(mod);
}
run_all("Backend Compliance (Tier 0)");

// --- Tier 1: Cryptographic Plumbing ---
clear_tests();
const plumbing_files = [
	"unit.crypto_plumbing_test"
];

for (let mod in plumbing_files) {
	require(mod);
}
run_all("Plumbing (Tier 1)");

// --- Tier 2: Business Logic ---
clear_tests();
const logic_files = [
	"unit.oidc_logic_test",
	"unit.session_logic_test",
	"unit.config_logic_test",
	"unit.utils_logic_test",
	"unit.security_logic_test",
	"unit.fuzz_logic_test"
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