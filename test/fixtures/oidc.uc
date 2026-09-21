/**
 * Static Fixtures for Tier 2 (Business Logic)
 */

export const MOCK_CONFIG = {
    issuer_url: "https://trusted.idp",
    client_id: "luci-app",
    client_secret: "top-secret",
    clock_tolerance: 300
};

export const MOCK_DISCOVERY = {
    issuer: "https://trusted.idp",
    authorization_endpoint: "https://trusted.idp/auth",
    token_endpoint: "https://trusted.idp/token",
    userinfo_endpoint: "https://trusted.idp/userinfo",
    jwks_uri: "https://trusted.idp/jwks"
};

export const MOCK_CLAIMS = {
    iss: "https://trusted.idp",
    aud: "luci-app",
    sub: "user-123",
    nonce: "n",
    iat: 1000,
    exp: 2000000000
};

export const MOCK_PRIVKEY = "-----BEGIN PRIVATE KEY-----\n" +
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDslpnpSiqifxBs\n" +
"wdqkbPnptDaM9mYg/rwdZpLDLCZDHvtlnwlmwqvBDM0mR6ciSNSuogrrXkyEjqeE\n" +
"tJacMN2ZDwR7bXLRBoboX5gMd7fZ8fhEczAvgz5X6841wv5PXpyXQoXQd36YIHlS\n" +
"h6EkHDj1FVraSJUGFM1/Fyuy48z+10C0p6Yg/Zj3HN9JGtj6KMlSJmdP6GwQAwK/\n" +
"CM7MSs5tQHyfh3swAQ2cVrrCw3FitZQlw17uMdpxtXDwFuxBTroAtPvSYXZa0IMB\n" +
"bPhA+kms/hwVeeDxI7ZaWSzbwBfYtalbF06BbyacapbAB9SOvKi0Ah9WPH/IT1+Y\n" +
"wH1plvNlAgMBAAECggEABw0JTZJtc9tSliiEMiCh+sI+r/PLS7zGcXU0TDHIJXmf\n" +
"vMHBH3lkx1jw0kJna5ZSaa6gTFnKm6wUDQNEISffACfvlm1xcw5Sk0v/YDu/Kcp+\n" +
"1NdpU7kscKVb8hk7crUbTfITF96VJ3EsUcvYqcFXkeJO4LDcvsom7Qc3668YqxhD\n" +
"hNl9bxu1HGYoLPKswP2TzKHkALyGzAhRmIxgDra1GJ+DEPsDSuCQda1BgkA1hz+o\n" +
"rEwr+8oqAapF/kD/6hCI01NX7OkAyiThRN8lQXcDG6gKHjuEuP1FPa75hFGxPEu+\n" +
"hyt1mJRTgbamK+F0vSVLE2Ljv8AEk6aLufn75XNRYQKBgQD3wmbSA64FBjqUlm1i\n" +
"Kwr0Io1/rMZmFXmJGtc5pTASMs0k7jcdg/pSrDRCisGnzNoJj+tUduBu65N2YrUG\n" +
"en9qeSKU1gqUBwubHslGOZrn1ygonZusgWHO7cIs2G9rWT5lLQDAfkp9blbucg7v\n" +
"2lYaJ36F745KVQUXlEiqdPZUMQKBgQD0dRS69Uta3kJEst8422/0DA15IRYoPtpD\n" +
"MxWx2GJu5dphvgRrUU0t8QYczBCVYbYQ2X724FQtZc8wEZEPeFPx/IHVNBjL8FS4\n" +
"0gE9hAGSHLmPeHCdcZ168teMFmFP/IfIQ+9DwamY8a1Z5kIJQnm1Jaavqh/TJfF5\n" +
"6IA6qWjJdQKBgGtTtYLowSvABQR1HbFXAAm+JhnW2KNETj/Mdsur+WUIyMFkyE9q\n" +
"6reBjan9veJY5WMbC1Ctpo+mUV0JaW4DBssy6n4bMr3pR2fNMFfRgH9KP0VI8TUL\n" +
"Xzlq2aDfqXSRVmwx0I+SpeYsNFBa7ImOxZnS3gZbPgKJTglm3QuqW0MhAoGAKMu1\n" +
"NvIirjpzQrW7LOjqCQdN5E4SPYsnr5lB4Jkk7C7tv+wPHr3FrIoRpBKmHdfdo3g4\n" +
"iQis45qe9f2ogLVrBPJH1IXKMZac/O8HB/YUsQacLQZDfPLt/guyzw0ZFlkla9Vy\n" +
"g5M5M235qQwVLyhp2UI8TAqPHxSw9NBJPgDxnNUCgYA/o9931tBTdsVjMcjrAllm\n" +
"n84AJspExNX1gNR68Ds9pX2FO3IU4eb9CACsoJRSeQ5qQC7p5TdTsDNo2qcJJEGq\n" +
"vNjPzhfEf4OxbGmK07euaiF9KZP+QCw4eCWQWD1z9rJt6vEr1/iPXu5ciCzTAYvc\n" +
"Qk7lb6SmHGOUr2JnawTxiQ==\n" +
"-----END PRIVATE KEY-----";

export const MOCK_JWK = {
    kty: "RSA",
    kid: "test-key-1",
    n: "7JaZ6Uoqon8QbMHapGz56bQ2jPZmIP68HWaSwywmQx77ZZ8JZsKrwQzNJkenIkjUrqIK615MhI6nhLSWnDDdmQ8Ee21y0QaG6F-YDHe32fH4RHMwL4M-V-vONcL-T16cl0KF0Hd-mCB5UoehJBw49RVa2kiVBhTNfxcrsuPM_tdAtKemIP2Y9xzfSRrY-ijJUiZnT-hsEAMCvwjOzErObUB8n4d7MAENnFa6wsNxYrWUJcNe7jHacbVw8BbsQU66ALT70mF2WtCDAWz4QPpJrP4cFXng8SO2Wlks28AX2LWpWxdOgW8mnGqWwAfUjryotAIfVjx_yE9fmMB9aZbzZQ",
    e: "AQAB"
};

export const ROTATION_NEW_JWK = {
    kty: "RSA",
    kid: "new-key-2",
    n: "xPB1NHleFyoWV4hBA3IT2BTYpxkSuSc2d0GBa_3ROHDM88mz79N-XYlZZmbX5ox-D7ESi_DwjvR_GOB5N1hETv5k_0O9zu9umIfXimm2cz19HjQ09NeF8ijZJWkNkzjALoe3-eu6WUuO-xjdyd-ANssahBzG_-WUOU3SZf6Q12ca_qzmhmVFuVVm5yXECWdS64ogFN6dMeXIJ2T4I5GPBkFxAFQiU8qe_ohWsY7dBiFCLkcpn1sYqoGa--t2uRI6yNIv1SdBVwcU9L32n4X9nkq_FLlrvcBvbqcf-i5yBcaBjqVEYCjpotbDLwXdArltdRPhMZIXXMXTJSVuu7Q2NQ",
    e: "AQAB"
};

export const ROTATION_NEW_PRIVKEY = "-----BEGIN PRIVATE KEY-----\n" +
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDE8HU0eV4XKhZX\n" +
"iEEDchPYFNinGRK5JzZ3QYFr/dE4cMzzybPv035diVlmZtfmjH4PsRKL8PCO9H8Y\n" +
"4Hk3WERO/mT/Q73O726Yh9eKabZzPX0eNDT014XyKNklaQ2TOMAuh7f567pZS477\n" +
"GN3J34A2yxqEHMb/5ZQ5TdJl/pDXZxr+rOaGZUW5VWbnJcQJZ1LriiAU3p0x5cgn\n" +
"ZPgjkY8GQXEAVCJTyp7+iFaxjt0GIUIuRymfWxiqgZr763a5EjrI0i/VJ0FXBxT0\n" +
"vfafhf2eSr8UuWu9wG9upx/6LnIFxoGOpURgKOmi1sMvBd0CuW11E+ExkhdcxdMl\n" +
"JW67tDY1AgMBAAECggEANn1loHg4PWaKuftcKazlqrLR4yH/2TTtT//S5GNdASXM\n" +
"v2M+owu8efrnvnqUIBkdRBA1Vnz6wkMJ64MoZtTISab/oNVIbjo3OoLTc1uefLI1\n" +
"rSa6xEfhqsf8lOpFNEfOfNFWaRL9A3nxfK47p4BshDycAJPJx8HoyhYrMcdGoiJK\n" +
"7r6xAT5joj++MGmtTKd34xVqocQTVBVCId1jH87GwsvGrvs2FdtpuWCtjqa42ZDD\n" +
"wsFkw/Jx1m0HdUBnDpH8DHE24JBzZ3YgNpt2BCxtYiOniLLGQhnr17XFVSNpiq4b\n" +
"4SzNW5LLPFWmtugx67xp65jYhgAKuxaiTqSKs8Ty3QKBgQD8XWtC7zeHVcgd63Bf\n" +
"dqmX5SKdAIQ70wP0b5sUqKJVLwMzFtIgwuOYORQv3vjqjKbChUybPkGfNcrDAWog\n" +
"0t+YG+H4ZU1QVMOPjYI3yG0zWLLbQ4Cv/5RJQU+6DB/sR5LT6iCnPwRGoBt1bM38\n" +
"bJeKxzgT/44KFVK5ho9sPsSlPwKBgQDHxqj4tVQ3e7doIAksLn4/soLu2l/73FNY\n" +
"mAtTQ1btlPdSIeVwBggcUXSP3oom0dV0q0N+/GharkK9WSO3IS6L8I81OTl6ToVt\n" +
"lxHHOz41dguiFE44sCadnqvZ0zjhc5uXoPqajgEP9O0KWhX7jXkua+rLBfz7i5A4\n" +
"QF19qZFDiwKBgQCwMpVaJWUSs3zGDwTlUhc0u0GAdsTcdAcV2fpf4SF98hX8zJkn\n" +
"UIrRVEDY74fBUzR3KdSDq2LrwwXvQwSTKEf+jrEl2ayyQoxLpRRe2CwOJoax+h5W\n" +
"Q06IGvaMQjzjnlFQbe4gdyoIGW8yfCYRcMwZk+B+bfYA6kRYzi9C90waxwKBgAgx\n" +
"nbyVs16TNHKQ3c9yGLuEFtq1Gjq6TrDTi6Nen7Ie6gX0XfS6SprevGkqN4BgGuEu\n" +
"JRaQQ7d0bkhV36EjO0WCGF2We0UI83ALQi9pvqNytAdxzcOFdhAA8gt9Hlgg5cDS\n" +
"WXT9Xg3Jfe9uwngO1WmSA49QL5AhqUilWzBMRCkBAoGBAM8zAhqSL3l5DxkqP/r1\n" +
"61MqnCEjnonEgfXyNcFc/frTx63nFYSGqny9v1916cHmNr8gTPhejehaFQR9q4l3\n" +
"M7cTfOgIjd6WSfKQc6imDlk3A3/5DA0h3YDR6mrk1d/gGe7xaWbamd46PQ6FFCDJ\n" +
"/nqZdYabbsVmOT3WGkzWwgzh\n" +
"-----END PRIVATE KEY-----";
