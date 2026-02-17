import { run } from 'testing';
import * as fs from 'fs';

let base_dir = replace(sourcepath(), /\/runner\.uc$/, "");

// 1. Collect environment inputs
let modules_env = getenv("MODULES");
let modules_list = modules_env ? split(modules_env, /[ ,]+/) : null;

const options = {
    verbose: (getenv("VERBOSE") == "1"),
    filter:  getenv("FILTER"),
    modules: modules_list,
    prefix:  base_dir + "/"
};

// 2. Define the authoritative suite structure
const SUITES = [
    { dir: base_dir + "/tier0", name: "Backend Compliance (Tier 0)" },
    { dir: base_dir + "/tier1", name: "Cryptographic Plumbing (Tier 1)" },
    { dir: base_dir + "/tier2", name: "Business Logic (Tier 2)" },
    { dir: base_dir + "/tier3", name: "Integration Tests (Tier 3)" },
    { dir: base_dir + "/tier4", name: "Meta Tests (Tier 4)" }
];

// 3. Execute and exit
let success = run(SUITES, options);
exit(success ? 0 : 1);
