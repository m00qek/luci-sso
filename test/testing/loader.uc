'use strict';

import * as fs from 'fs';

export function normalize_module_name(path, prefix) {
	let m = path;
	if (prefix != null && length(prefix) > 0) {
		m = replace(m, prefix, "");
	}
	m = replace(m, /\.uc$/, "");
	return replace(m, /\//g, ".");
};

export function load_suite(dir_path, prefix, error_cb) {
	let files = fs.lsdir(dir_path);
	if (!files) return [];

	let test_files = [];
	for (let f in files) {
		if (match(f, /_test\.uc$/)) {
			push(test_files, f);
		}
	}

	let loaded = [];
	for (let f in test_files) {
		let full_path = dir_path + "/" + f;
		try {
			let mod_name = normalize_module_name(full_path, prefix);
			require(mod_name);
			push(loaded, mod_name);
		} catch (e) {
			if (error_cb) {
				error_cb(full_path, e);
			} else {
				print(`\u001b[31mError loading ${full_path}: ${e}\u001b[0m\n`);
				if (e.stack) print(e.stack + "\n");
				exit(1);
			}
		}
	}

	return loaded;
};
