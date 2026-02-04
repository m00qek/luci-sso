import { run_all } from 'testing';
import * as fs from 'fs';

// Find all test files in test/unit/
let files = fs.glob('test/unit/*_test.uc');

for (let file in files) {
    // We expect to be run with -L /app/src -L /app/test
    // If file is 'test/unit/mylib_test.uc', we want 'unit.mylib_test'
    let modname = replace(file, /^test\//, '');
    modname = replace(modname, /\.uc$/, '');
    modname = replace(modname, /\//g, '.');
    
    try {
        require(modname);
    } catch (e) {
        die(`Failed to load test module '${modname}' from '${file}': ${e}\n`);
    }
}

run_all();