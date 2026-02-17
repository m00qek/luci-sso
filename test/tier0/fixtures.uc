/**
 * Golden Fixtures for Tier 0 (Backend Compliance)
 * These values are mathematically verified using OpenSSL.
 */

// --- SHA256 Scenarios ---
export const SHA256_STANDARD = {
	msg: "compliance-test",
	hex: "dd372bc3584700eb76e20ea1dde0a36ba5b647bd7059f934c52c89e2c5cd521f"
};

export const SHA256_NULL_BYTES = {
	msg: "null\0byte\0test",
	hex: "4c9cb0081d7d0759f05eea7e4859e8942e49d19d4a874263e6645236a17b72c0"
};

// --- HMAC-SHA256 Scenarios ---
export const HMAC_STANDARD = {
	key: "secret-key",
	msg: "compliance-test",
	hex: "92245db3449d3d562bff80bb484d0669f58f335a34501bba67e500654305d13d"
};

export const HMAC_NULL_BYTES = {
	key: "key\0with\0null",
	msg: "null\0byte\0test",
	hex: "511409bf8cfd63fbbffd3b314d3b94cccda83efdaeb7ade0c19ca2d7e523daac"
};

export const HMAC_LEADING_ZEROS = {
    key: "\0\0\0secret",
    msg: "\0\0\0message",
    hex: "197c3867dee3c220262b1f618eac628765262480138b212cc9042c76cbd95d0d"
};

export const HMAC_LONG_KEY = {
    key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 100 As
    msg: "test",
    hex: "d1ce3d8e2e8e805f3f965e7c4e6e193bc9b5c646bfeac9686c7957f9514bc396"
};

// --- RSA Scenarios ---
export const RSA_2048 = {
	msg: "compliance-test",
	pub: "-----BEGIN PUBLIC KEY-----\n" +
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6F5srqyBtaZckA8bTsNo\n" +
		"HpU45jG3UWZD6oqx5hICzdjEH/tWCjz/1cwvw1RkeDA3WOpFO7x/F24rF10waLOU\n" +
		"57m0g63s9o/V1STC4c6oISRczl/iuYYl07ikcNRgRlsJ+Kb+ck4GsoXn9YypKwgh\n" +
		"jKj9erZIEJi3Moqgg4Bpwyv3gD8kjaf+bLtBvk20boJ2yPAK2s7zqaZscv61mEDr\n" +
		"4NrDbZ3BC+lJxHvR4pitaVwlija7hbndO8DehjyyxJBOvfreJVymXqBVSguY6+Vk\n" +
		"gIR3bonCyKx+U6D01bL5K6zPKADY6Q+STioBivUokpqvnhvmz3C6GJVsSjikayvj\n" +
		"ywIDAQAB\n" +
		"-----END PUBLIC KEY-----",
	sig_hex: "26e3f6bdd5cb131a2333d52fbd2cec3b3011017763700acae4a4ede6e2bde8fff6fb09065a18f80c09bbd1aa546fe37b268eb9d4b9e351354966c30f7e3013d701b58c90930d32519c3c880f3f97af602a65d857cf4ff42c998ed5cd9a5739064c2ccb2c010e42d455d887a1765ebfbede57aa2373adaf48596ecf9c149330fff579ad76bfc6b1b63d465b52209cc5ffd4ca909db0ccc9b6219fb5b13a131c6bacefc576d224c71f1e06461002f411a0f1f855ae429436bd86ef55807e4d9429d83528e3e3fa06c6f2cb32c9d17c9be87d535a8a70dc0095d99d368cca4efbc3d7f1c817c61dc05ffd77aae3ca41e7088648dfde43e37b9eb5cf5cd8e41346b7"
};

export const RSA_NULL_MSG = {
    msg: "null\0msg",
    pub: RSA_2048.pub,
    sig_hex: "387682bda40d8049b5e4d6c2ceba4d76506560dde910c55f1cb56d50bec3374a621bae52d1f628f0440672d1d827d440e5b46b6e4ebe7fe4519d8acedee18bd69751eff38affa5493e8f14162617f7f1df1974a3c5e1700b6c74da81627ff07f7aaf1f4b4fec754c53c80ae2afe7e74945282c0d0661b75cdd6f50f1d63d0c3732fcabe0c8bda3deb28617a681be1ff00967fdf95173e556a9869f13b87c32839f39b79280cdfb137c09447591ccbcd18c9bb80151a61a4add23de8033763f025b3621f0ed3f25ccb52939b381b7262edf5e591008cac6ba238f6719813fc28e67ed4e7e92cb2ef11e5f7a2d99e91806726dc52d71a7484cf9359ce0f3232d4e"
};

export const RSA_4096 = {
	msg: "rsa4096-test",
	pub: "-----BEGIN PUBLIC KEY-----\n" +
		"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1Mp25S6IHAqDRyb52VQu\n" +
		"K2H9a4EY1e/gkEAC6tnkaZZXXeXb/Jvhy7z/DEFpv/uz8tAq07fwXAbo0ZrPhnBX\n" +
		"x8yWFNzTEmMoxt8cXv1IWwqhaHr7oX32i3vdc4B4IHvhEc22TjL69LWGpXZuZyav\n" +
		"A0wSzSIIs8dUxUFri+UVzeiNfQPfjdXR9p9s6luw5XPL9GyaitCUmFbEWMFsjuWY\n" +
		"Y1IipQQMNAtXTF2Y3ynQws+V/0YEpzYhSV8yWlNAZTQwLXIfm1tHBSQtJfPEmdXi\n" +
		"vCrcHj3PqJc+l5MlTvn/LZh/LFnVXtQHg9r4oAVTVk3kHpCHdd7v6PNoF4+UQc08\n" +
		"9oImXy1kIUAg8bG1oNB6G57jtACei66pxOpyD/cuv4B6tVm+w9eqsluTHmkdw1HH\n" +
		"FjcjJrXRumXnYjEG7mzqjHlW0Ic8zXyInyFf2B8rP/FlPy9kKkziGiyy/sbnOvgR\n" +
		"JWgzt6VZBHa1oKrz4qm+96yP0UGu7beplXKxl1mHGmujBOJAAdgD0Ppq2+9LG09M\n" +
		"j7Tu+jD85hkNfhUiAaj7DGRzOQc1JiB96TEsQGXGUWjExM7jx6HtzOtw3XeK76Qc\n" +
		"6Z43OgLACyBGsAEdavB9rbBIBylXwGCL3YfaNmXkCt2ZJKZB4FBrvZTNxUwNbYUT\n" +
		"i1n8La/AZXa/8Seb8LyG6sUCAwEAAQ==\n" +
		"-----END PUBLIC KEY-----",
	sig_hex: "851b8fe9aeaf3682999f847aa2f52e6a81902dbc56c298c4acd1144e78a8b90104356203658e564d73174db588cf2f9c65a3f76da63595b97d0dcf393479fd2d86f0d4c154ac22396c93bf64710e892ec79ca45a169a02ed41049ff9971d4fcb442f0815798cad34fe8636a833de85172f816976c66c432fc0110cc2d10a2607dfd59ccaed0c5cf64603bb47bf3137b6a981608598abfbc0b618eb6b627c275f95135555eb7b7cec8f2e2f90a8d7fe3de9863096fab25005f97d66dab2684320949b02e9ddff4e00aa09dcb470505535c9108ac9f20b5afe8d7d7ecf2dc7c4856211ad4787e87cba22cb221d10b24de5e037b352acde23ed11429203b3ff59f5dc9acefd060d1e298189e24f251a52ed6bd36e151551e7a183d759f0525816e38976fa3f529780d17f2c1273210cc0f06f8f60ab109bf580bf5efb89ffa7ba48a019869e1927e6ee0aa083c94512e0c3e150f9b408134c8949e4c482b7547312f25055f8ee0784962715231f48316c04905caa5f8adbd43160ae7a39ee2fe3261697796b543e3fd5a0a684d9598f27f30d5adc71b3205c5050ac447db9de585a151f2675772f57b2c744905ddcf70c995d5be6ea2c78e85aa855745f743184385481dd07aa5fc897dd1296896c9eb952ac4a96ffff4d0d79d5f963ccb99474b9f1d8a04d95182f31d0625dddfe5baa714efe0ac43b0f156ce695a3767323f83c"
};

// --- EC Scenarios ---
export const EC_256 = {
	msg: "compliance-test",
	pub: "-----BEGIN PUBLIC KEY-----\n" +
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKSZQ954ztU8Nmg+PZDfFmi/8XNZ\n" +
		"f4Xap9aATkxlnM4UHtEi57z/ok0143yBgwv5uABqmsv2D834CoYkBeNX+w==\n" +
		"-----END PUBLIC KEY-----",
	sig_hex: "ca1ba5225e59a3b20946a192ce3de174b6f3a682d12dfb78dc310ea164d3011106f878e90bd9505bc8a1d57b7458691fe861068b2c67b3a51719f3add49d544e"
};

export const EC_NULL_MSG = {
    msg: "null\0msg",
    pub: EC_256.pub,
    // RAW R|S (64 bytes) converted from DER: 30450220463e80e851716bc131dd4096ab0e36bdcc865c5bdbe7be2d260a4ba32b2d4093022100c61a51ebaaa8b490b2d1715757c319d289c60b84ba0d8920f0c43faa493ac7eb
    sig_hex: "463e80e851716bc131dd4096ab0e36bdcc865c5bdbe7be2d260a4ba32b2d4093c61a51ebaaa8b490b2d1715757c319d289c60b84ba0d8920f0c43faa493ac7eb"
};

export const EC_256_LOW_BIT = {
    msg: "compliance-test",
	pub: EC_256.pub,
    sig_hex: "df41996e470c5117ab3849a79065afe180126ffad08a3d599705539366e3c2c764629c6fa4482dfe0b516694dc7b890b28de9cfdacd6a98a62100d55f49f0738"
};

export const EC_256_PRIV = "-----BEGIN EC PRIVATE KEY-----\n" +
	"MHcCAQEEIInS/6XNoDRZ6reZIDPhZunZfRTguDRSkTMZfXQZ6NoBoAoGCCqGSM49\n" +
	"AwEHoUQDQgAELKSZQ954ztU8Nmg+PZDfFmi/8XNZf4Xap9aATkxlnM4UHtEi57z/\n" +
	"ok0143yBgwv5uABqmsv2D834CoYkBeNX+w==\n" +
	"-----END EC PRIVATE KEY-----";
