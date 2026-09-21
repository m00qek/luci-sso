/**
 * Public crypto façade for luci-sso.
 * @module luci_sso_crypto
 */

import * as c_base from 'luci_sso.crypto.base';
import * as c_jws  from 'luci_sso.crypto.jws';
import * as c_jwt  from 'luci_sso.crypto.jwt';
import * as c_jwk  from 'luci_sso.crypto.jwk';
import * as c_hash from 'luci_sso.crypto.hash';
import * as c_pkce from 'luci_sso.crypto.pkce';

export const constant_time_eq = c_base.constant_time_eq;
export const random            = c_base.random;
export const safe_id           = c_base.safe_id;
export const jws_sign          = c_jws.sign;
export const jws_verify        = c_jws.verify;
export const jwt_verify        = c_jwt.verify;
export const hash_sha256       = c_hash.sha256;
export const hash_sha256_hex   = c_hash.sha256_hex;
export const pkce_pair         = c_pkce.pair;
export const jwk_to_pem        = c_jwk.to_pem;
