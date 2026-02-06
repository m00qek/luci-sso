/**
 * Golden Fixtures for Tier 1 (Cryptographic Plumbing)
 * These values verify the ucode-to-C handoff logic.
 */

export const PLUMBING_RSA = {
	token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qtO-zazDyKOQa176gjZMLWufxHbXVev3uK_vjAhynRiFuLdtO7h2zBZg-SPqv-AQcNIw0gmuUdv36ba2-MaTQ5QV0GOiB7wJBFOH4u-CmcPhCmQ4Zojd8D8zuXVxhYOSgscRacirbk1K_UfTA6m4AoWkpoJaAMQhpMLBY8JgwC3rfRKqhOsCKvAO5nVeJvcfkbEM03k-hvLTpKjz_kRjijVeaxCN4fx1c4TXiDgc70xt--Vj_0-RGgIueuEttxwpArT7-4zx4_mnRnteGcJdEjHKUbt4QOBOS5f7j0MKjYkarzOiaf8ZqX0gUPBREQnmhXE7pAge9cv2C9OiIVm71w",
	pubkey: "-----BEGIN PUBLIC KEY-----\n" +
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq0g5x3uxj4F9zmlMbadq\n" +
		"N8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8+rD/2du7uA76nmUzoUB\n" +
		"t3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE/Rviv3XQ7YbXZe55pRcvNjcx\n" +
		"wSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR/QQO9mLcjjuO7\n" +
		"ta/ahC8pbGOOIOk7AtCd/KV56tk1Tid5iaYV8RIhXSDeef9q7+L9DY6pK1Mx2Yu8\n" +
		"SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91\n" +
		"pQIDAQAB\n" +
		"-----END PUBLIC KEY-----"
};

// A JWK Set containing multiple keys to verify lookup logic.
export const JWK_SET = [
    { kid: "key-1", kty: "RSA", n: "...", e: "..." },
    { kid: "key-2", kty: "EC", crv: "P-256", x: "...", y: "..." },
    { kid: "key-3", kty: "oct", k: "..." }
];
