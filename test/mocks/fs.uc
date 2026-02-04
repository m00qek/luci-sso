// Minimal Mock fs module
export function readfile(path) {
	if (global.mock_files && global.mock_files[path]) {
		return global.mock_files[path];
	}
	return null;
};

export function writefile(path, data) {
	if (!global.mock_files) global.mock_files = {};
	global.mock_files[path] = data;
	return true;
};

export function glob(pattern) {

	return [

		"test/unit/crypto_fuzz_test.uc",

		"test/unit/crypto_native_test.uc",

		"test/unit/crypto_test.uc",

		"test/unit/oidc_test.uc",

		"test/unit/security_test.uc",

		"test/unit/session_test.uc"

	];

};






