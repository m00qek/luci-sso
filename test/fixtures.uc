// =============================================================================
// RS256 Test Data
// =============================================================================
export let RS256 = {
    PUBKEY: "-----BEGIN PUBLIC KEY-----
" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqk1WZcjtRvPjwcN3WMk2\n" +
        "CRGeP5oCjIPNNuo87E0BFT3UdbNsLx44B+yGosB/FhwY/hKV8bXAopmA46wirqd/\n" +
        "azZH4sjsWTQs1uhtRI6GxR5xnoIFV4gRrMkqGkRLMTCeUajsxGw/jMlEzmyDwW+t\n" +
        "/ZPu7POBeuH3ki+wog44uKU22zN+1iigpUmJpBjUpg/hxin9s4dKAUavCJmwd+Bu\n" +
        "KX1cOY5pjP9wx8iJvssyv9vwosxR47107HKokkbOOGxiMLToG6SiQbWfslRwgw+r\n" +
        "iyqg2OlAgir5e1C0Bcd/qnTgNf9Vkv6v+n1dsDaWz99s4/LHr3AiP4LIeSuiYNl3\n" +
        "XwIDAQAB\n" +
        "-----END PUBLIC KEY-----",

    MSG: "hello world",

    SIG_B64URL: "A4WLYP1G7SK3zpg7Ni_le_B0LzUUu1uLbFu1HXAApX3hkUiQLl1c7PWqMe408RqK-MqBiTB3mqJ9fXY1Z937kamwY5ycD1gMhyhfa9CgqrLA6jTZojcCanKqu13GWhZCNB5QiGu8O_sY-CUew-F32yef6rrx896BkfiB7Tyovg_jhsXEPyGX_Yf3CCPfGcMcRf-2pFIX1pnulUPgxVVIbidAuJ1SHxNI7UA3xTJq9phR5B_pnbNay1aVp50ewnKQoGFJj9EabFBVMkeRUCON29ZSt9YgDd1-0swWrZWEI3g3J25fbuVQS5IrxvLOZcjRE5zuc9m8RB4zY4PrbLQwQA",

    JWT_PUBKEY: "-----BEGIN PUBLIC KEY-----
" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq0g5x3uxj4F9zmlMbadq\n" +
        "N8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8+rD/2du7uA76nmUzoUB\n" +
        "t3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE/Rviv3XQ7YbXZe55pRcvNjcx\n" +
        "wSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR/QQO9mLcjjuO7\n" +
        "ta/ahC8pbGOOIOk7AtCd/KV56tk1Tid5iaYV8RIhXSDeef9q7+L9DY6pK1Mx2Yu8\n" +
        "SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91\n" +
        "pQIDAQAB\n" +
        "-----END PUBLIC KEY-----",

    JWT_TOKEN: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qtO-zazDyKOQa176gjZMLWufxHbXVev3uK_vjAhynRiFuLdtO7h2zBZg-SPqv-AQcNIw0gmuUdv36ba2-MaTQ5QV0GOiB7wJBFOH4u-CmcPhCmQ4Zojd8D8zuXVxhYOSgscRacirbk1K_UfTA6m4AoWkpoJaAMQhpMLBY8JgwC3rfRKqhOsCKvAO5nVeJvcfkbEM03k-hvLTpKjz_kRjijVeaxCN4fx1c4TXiDgc70xt--Vj_0-RGgIueuEttxwpArT7-4zx4_mnRnteGcJdEjHKUbt4QOBOS5f7j0MKjYkarzOiaf8ZqX0gUPBREQnmhXE7pAge9cv2C9OiIVm71w"
};


// =============================================================================
// ES256 Test Data
// =============================================================================
export let ES256 = {
    PUBKEY: "-----BEGIN PUBLIC KEY-----
" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnaYU+sbeE7uZ/zGoRVfCurxTkjUZ\n" +
        "W7wCr58/eqxxmj9X6OmCcIr9i8bzbS3zZwCGbt72gMfXW/hjUwA2VhrTBA==\n" +
        "-----END PUBLIC KEY-----",

    MSG: "hello world",

    SIG_HELLO_B64URL: "kknuSsOSyfDerTgtfm3suX9uNMviVkI899Y-duZPgx8KqzhWVTk_qpJBN6Bb2GvdYgfBFGjcEKOmtE1swUiS-Q",

    JWT_TOKEN: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlczI1NiIsIm5hbWUiOiJFUzI1NiBVc2VyIn0.62l8TeaDDc0cYo1d_w8agIskddI3aethFM_wz6pU_4kcg3QVrFLiNm5zbc9CxmzE25eaOidqEgWwBlbeRcJlDw"
};


// =============================================================================
// Coverage / Policy Test Data
// =============================================================================
export let POLICY = {
    PUBKEY: "-----BEGIN PUBLIC KEY-----
" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzHsmm0TIiDujMnz6HVQc\n" +
        "5B87SGsbKsIQxcCy4XBxNnYka96AjXUC4YzP4rBqefCpgCZIoJN3GSzzrhhd2V/s\n" +
        "BgOdcMGY7gWspWt2kTYJ3OqLz9ex2LcQI5ZAf9ggU0BF3DVALIVCl7+Ac52+diC6\n" +
        "7gMWYMsMZT2iZst9YdGs8NB1GMMzedTQYBUETlF35/wwJSeGRLoWRDa6vnQFe3Cx\n" +
        "MaXCXXU/6Ceb4ijfuIn3d6l7Y7YsTKJRyFUONazc4ZJRJaXoGekC8qQwyGthAwqz\n" +
        "WT8aeB1VysymBC12bTRExlP4mPSsgs60dWgC2g9JXB9IJXTUjtRHMpDbZ5YyDj8o\n" +
        "TwIDAQAB\n" +
        "-----END PUBLIC KEY-----",

    JWT_EXPIRED: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleHBpcmVkIiwiZXhwIjoxNTAwMDAwMDAwfQ.SU7zYwroXjhidGEL7vZHNfxCmQO8_3pQ94qnp_LUgBYLH0WIjxA8qPVtj47VO9mJzeDMkuEu6Pmx3Ueo2Xc2DCvjBhYQU4oAkxP3O2K9cgRbHdcrMv7gsGiRlrooUH61QoHUBg9qB1vp3Q5NmUsGJaCOftEJ_cvVPT5NOSFEFjf3axp06E9iQtWNzRIsQtxOLmMzyVekD5PUB5LeBhHRnQjwystOm_rumj520YFEAMJSL1gEI6gD3PMTib65r4YxsUSGMuwgDK_qxYVE7mtmt15_y9koMlkSGoZK_sxZZhljQ2dD1WGACSl_e_IeZE1ukpNq3aiuCNhXSkUdIAbyEA",

    JWT_FUTURE: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmdXR1cmUiLCJuYmYiOjQxMDI0NDQ4MDB9.vcrwMfCmPUuMlvc-IqVwslSlMao8M_dDc77Vi68fJ1ANlua9SJPJYcoI6h_f39KlBkgHVXzF-z57RFREKUKpsXbnjKTTCu2aeZDWPn6fEGHV0MGno5QHtdIzdeQg0W9z6KkIZFGrVAblWaMeyot4IkXhF-BGwJhtGPNHrg77H184u3MLvam1r32bQuKkL3MFhRaEPnmOqIDSpZLLhobBk_w16ZpyvsRJLlYFqmVV6DtjOdUGZeFS3gi_QnNpZJWxucI-vn3oLzCTB1TfrjK1_O21t7yyji69d699IlunpoXvXiBopF1SJLtV_Qfk0vpwGpAGuYccX8Iy4eZgJgsWOQ",

    CLAIMS_PUBKEY: "-----BEGIN PUBLIC KEY-----
" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5GOVLdP4p4FvHK/9fQAO\n" +
        "wY9v3WmuSib2Mqs6Yur1Wc0xo+PX2Po+nCkgCylHdlTVM7eCHxoQU2A6a4Mo2RJ+\n" +
        "DPW8dkmbvtWoaa9OBGnuylb7AcAxTUSHqtJLaV+uG4UEFBCxslnHRE6Ny+vQ4OGd\n" +
        "Qpytfti1rvqyRtPmzOm+qlziuCxoHjxA4BD41W71IWlWjQOibY3JFtKOW7Jg5UiQ\n" +
        "5AWfEW1q12MiI86aVPYvhwKeE19e5Nn1olGDljAJAUNBxUifrPeS8gy2XB9hpj+2\n" +
        "zl3j8aIu/qUcUYsiyK+YXhyRp7LHHEo/Jv4nVNSuJYiz4N6vBZA65PgfLiIfeBv9\n" +
        "HQIDAQAB\n" +
        "-----END PUBLIC KEY-----",

    JWT_WITH_CLAIMS: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiSm9obiBEb2UiLCJpc3MiOiJteS1hdXRoLXNlcnZlciIsImF1ZCI6Im15LWFwcCJ9.NTGANs4kmqZP_kvN_6NF9XIWw2GnlnmNNtn4V5hNa7rcJdigyLTNBXCIGM16UfUQ-9r86kGBsmbAQ4pVV-mf8iI0CLP_jjh93I149zspPjAQBH5d8lO-iCGPRQ7nSB5gw3JOBINmg25WRpKCnwsEE4cumpUonlm3MpZRDt9kd8FY3H7oA4zQEUmPEhx4tAUyAbyxBEcs_XwRmXt58w5s3DIz8KkGJuRi2mNl5LG1f-mlNiY80Rc_dCdq_wttQcjbbG01bEhHZH7KxrMfbpC3xPIfvW0-WJPNBYnufpI7swjvn9-BydlAVbgnnifmUuf3hAnlKDI40xqczlNEaqY9Xg"
};