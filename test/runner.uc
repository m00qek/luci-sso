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
	"unit.native_hardening_test",
	"unit.native_jwk_test",
	"unit.native_weak_rsa_test",
	"unit.native_compliance_test_extra",
	"unit.native_memory_safety_test"
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
	"unit.encoding_security_test",
	"unit.encoding_url_test",
	"unit.encoding_url_normalization_test"
];

for (let mod in plumbing_files) {
	require(mod);
}
run_all("Plumbing (Tier 1)");

// --- Tier 2: Business Logic ---
clear_tests();
const logic_files = [
	"unit.oidc_logic_test",
	"unit.oidc_url_fragment_test",
	"unit.oidc_security_test",
	"unit.discovery_security_test",
	"unit.discovery_resilience_test",
	"unit.handshake_rotation_test",
	"unit.handshake_dos_reproduction_test",
	"unit.handshake_warning_test",
	"unit.handshake_split_horizon_test",
	"unit.handshake_userinfo_test",
	"unit.session_logic_test",
	"unit.session_race_test",
	"unit.session_write_fail_test",
	"unit.session_expiry_security_test",
	"unit.session_security_reproduction_test",
	"unit.ubus_logic_test",
	"unit.config_logic_test",
	"unit.config_group_test",
	"unit.config_role_test",
	"unit.config_case_insensitive_test",
	"unit.config_scope_test",
	"unit.web_logic_test",
	"unit.web_status_coercion_test",
	"unit.security_logic_test",
	"unit.security_logic_test_extra",
	"unit.logout_csrf_test",
	"unit.logout_security_test",
	"unit.logout_security_reproduction_test",
	"unit.fuzz_logic_test",
	"unit.https_enforcement_test",
	"unit.dos_security_test",
	"unit.web_security_headers_reproduction_test",
	"unit.session_cleanup_reproduction_test",
	"unit.config_validation_reproduction_test"
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

// --- Integrity Check: Orphaned Tests ---
const UNIT_DIR = "/usr/share/luci-sso/test/unit";
let all_files = fs.lsdir(UNIT_DIR) || [];
let registered = {};

// Register all known tests
for (let f in backend_files) registered[f] = true;
for (let f in plumbing_files) registered[f] = true;
for (let f in logic_files) registered[f] = true;

let orphans = [];
for (let f in all_files) {
    // Only treat files ending in '_test.uc' as tests
    if (match(f, /_test\.uc$/)) {
        let mod_name = "unit." + substr(f, 0, length(f) - 3);
        if (!registered[mod_name]) {
            push(orphans, f);
        }
    }
}

if (length(orphans) > 0) {
    print(`\n\u001b[1m\u001b[31m🚨 ORPHANED TESTS DETECTED:\u001b[0m\n`);
    for (let o in orphans) {
        print(`   - ${o} (Not in runner.uc)\n`);
    }
    print(`\n\u001b[31mRefusing to complete. All tests MUST be registered in test/runner.uc\u001b[0m\n`);
    exit(1);
}