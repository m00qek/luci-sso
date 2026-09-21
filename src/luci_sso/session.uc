/**
 * Public session façade for luci-sso.
 * @module luci_sso_session
 */

import * as key       from 'luci_sso.session.key';
import * as handshake from 'luci_sso.session.handshake';
import * as token     from 'luci_sso.session.token';

export const get_secret_key        = key.get;
export const create_state          = handshake.create;
export const consume_state         = handshake.consume;
export const verify_state          = handshake.verify;
export const reap_stale_handshakes = handshake.reap;
export const create                = token.create;
export const verify                = token.verify;
