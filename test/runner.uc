import { run } from 'testing';
import * as fs from 'fs';
import * as math from 'math';

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

// 3. Helper to run a suite in a sub-process
function run_suite_isolated(suite, opts) {
    // B2: Use unique filename for sub-process script to prevent races
    let script_path = sprintf("/tmp/suite_runner_%d_%d.uc", time(), math.rand());
    let script_content = sprintf(
        "import { run } from 'testing';\n" +
        "let suite = %J;\n" +
        "let options = %J;\n" +
        "exit(run([suite], options) ? 0 : 1);\n",
        suite, opts
    );
    fs.writefile(script_path, script_content);
    
    let cmd = sprintf("ucode -L /usr/share/ucode -L /usr/lib/ucode -L %s -L %s %s", 
        base_dir, base_dir + "/testing", script_path);
    
    let res = system(cmd);
    fs.unlink(script_path);
    return res;
}

// 4. Execution loop
let overall_success = true;

// If specific modules are requested, we might skip isolation or 
// just run the normal 'run' if it's likely small.
// But for a full run (no specific modules), isolation is REQUIRED.
if (!modules_list) {
    for (let s in SUITES) {
        if (run_suite_isolated(s, options) != 0) {
            overall_success = false;
        }
    }
} else {
    overall_success = run(SUITES, options);
}

exit(overall_success ? 0 : 1);
