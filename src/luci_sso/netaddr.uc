"use strict";

/**
 * IP address and CIDR parsing, for the rate limiter's client keys and the
 * trusted_proxy option. Pure: no I/O, no state.
 *
 * An address is { family: 4, parts: [4 bytes] } or
 * { family: 6, parts: [8 groups of 16 bits] }. An IPv4-mapped IPv6 address
 * (::ffff:a.b.c.d) is always returned as the IPv4 address it carries: it is
 * an IPv4 client reaching a dual-stack socket.
 *
 * @module luci_sso_netaddr
 */

/**
 * Longest text accepted as one address: the longest IPv6 form, with an IPv4
 * tail, is 45 characters.
 */
export const MAX_ADDR_LEN = 64;

function _ipv4(s) {
	let m = match(s, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m) return null;
	let out = [];
	for (let i = 1; i <= 4; i++) {
		let n = int(m[i]);
		if (n > 255) return null;
		push(out, n);
	}
	return out;
}

// Expands an IPv6 address to 8 integers, or null. Accepts :: compression and
// an embedded IPv4 tail (::ffff:192.0.2.1).
function _ipv6(s) {
	let tail4 = null;
	let m = match(s, /^(.*:)([0-9]{1,3}(\.[0-9]{1,3}){3})$/);
	if (m) {
		tail4 = _ipv4(m[2]);
		if (!tail4) return null;
		s = m[1] + "0:0";                  // placeholder for the two IPv4 groups
	}

	let halves = split(s, "::");
	if (length(halves) > 2) return null;

	let parse = (part) => {
		if (part == "") return [];
		let groups = [];
		for (let g in split(part, ":")) {
			if (!match(g, /^[0-9A-Fa-f]{1,4}$/)) return null;
			push(groups, hex(g));
		}
		return groups;
	};

	let head = parse(halves[0]);
	let rest = (length(halves) == 2) ? parse(halves[1]) : [];
	if (head == null || rest == null) return null;

	let groups;
	if (length(halves) == 2) {
		let fill = 8 - length(head) - length(rest);
		if (fill < 1) return null;
		groups = [ ...head ];
		for (let i = 0; i < fill; i++) push(groups, 0);
		for (let g in rest) push(groups, g);
	} else {
		groups = head;
	}
	if (length(groups) != 8) return null;

	if (tail4) {
		groups[6] = tail4[0] * 256 + tail4[1];
		groups[7] = tail4[2] * 256 + tail4[3];
	}
	return groups;
}

function _is_mapped(g) {
	return g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff;
}

function _mapped_ipv4(g) {
	return [ g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255 ];
}

/**
 * Parses one bare IP address: dotted IPv4, or IPv6 in any standard form.
 * Nothing else is accepted: no surrounding whitespace, brackets, port, zone
 * or prefix.
 *
 * @param {*} s The text to parse.
 * @returns {?object} { family, parts }, or null when `s` is not an address.
 */
export function parse(s) {
	if (type(s) != "string" || length(s) == 0 || length(s) > MAX_ADDR_LEN)
		return null;

	let v4 = _ipv4(s);
	if (v4) return { family: 4, parts: v4 };
	if (index(s, ":") < 0) return null;

	let g = _ipv6(s);
	if (!g) return null;
	if (_is_mapped(g)) return { family: 4, parts: _mapped_ipv4(g) };
	return { family: 6, parts: g };
};

/**
 * Parses an address or a CIDR range: `a.b.c.d`, `a.b.c.d/0-32`, an IPv6
 * address, or `ipv6/0-128`. A bare address is a range of one. Host bits
 * below the prefix are ignored. An IPv4-mapped IPv6 range of /96 or longer
 * is the IPv4 range it maps; a shorter one is an IPv6 range, which no IPv4
 * address falls in.
 *
 * @param {*} s The text to parse.
 * @returns {?object} { family, parts, prefix }, or null when `s` is neither.
 */
export function parse_cidr(s) {
	if (type(s) != "string") return null;

	let prefix = null;
	let m = match(s, /^([^\/]+)\/([0-9]{1,3})$/);
	if (m) {
		s = m[1];
		prefix = int(m[2]);
	} else if (index(s, "/") >= 0) {
		return null;
	}

	if (length(s) == 0 || length(s) > MAX_ADDR_LEN) return null;

	let v4 = _ipv4(s);
	if (v4) {
		if (prefix == null) prefix = 32;
		return (prefix <= 32) ? { family: 4, parts: v4, prefix } : null;
	}
	if (index(s, ":") < 0) return null;

	let g = _ipv6(s);
	if (!g) return null;
	if (prefix == null) prefix = 128;
	if (prefix > 128) return null;
	if (_is_mapped(g) && prefix >= 96)
		return { family: 4, parts: _mapped_ipv4(g), prefix: prefix - 96 };
	return { family: 6, parts: g, prefix };
};

/**
 * Returns true when `addr` (from parse) falls in `range` (from parse_cidr).
 * Addresses of different families never match.
 *
 * @param {object} range A range from parse_cidr().
 * @param {object} addr An address from parse().
 * @returns {boolean}
 */
export function contains(range, addr) {
	if (!range || !addr || range.family != addr.family) return false;
	let bits = (range.family == 4) ? 8 : 16;
	let left = range.prefix;
	for (let i = 0; left > 0; i++) {
		let n = (left < bits) ? left : bits;
		let shift = bits - n;
		if ((range.parts[i] >> shift) != (addr.parts[i] >> shift)) return false;
		left -= n;
	}
	return true;
};

/**
 * Formats an address from parse(): dotted IPv4, or the eight IPv6 groups in
 * lowercase hex, uncompressed.
 *
 * @param {object} addr An address from parse().
 * @returns {string}
 */
export function format(addr) {
	if (addr.family == 4) return join(".", addr.parts);
	return join(":", map(addr.parts, (g) => sprintf("%x", g)));
};
