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

// The address in `s` as its eight 16-bit groups (IPv6) or four bytes (IPv4),
// or null. ucode's iptoarr() parses with the C library's inet_pton(), which
// takes dotted IPv4 with exactly four decimal parts, no leading zeros, and
// IPv6 in any standard form, with :: and an IPv4 tail, and nothing else: no
// whitespace, brackets, port, zone or prefix. inet_pton() reads a C string,
// so it would stop at a NUL byte: every byte is checked to be a hexadecimal
// digit, "." or ":" first.
function _parts(s) {
	for (let i = 0; i < length(s); i++) {
		let c = ord(s, i);
		if (!((c >= 48 && c <= 58) || c == 46 || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)))
			return null;
	}
	let b = iptoarr(s);
	if (type(b) != "array") return null;
	if (length(b) == 4) return { family: 4, parts: b };
	if (length(b) != 16) return null;
	let g = [];
	for (let i = 0; i < 16; i += 2) push(g, b[i] * 256 + b[i + 1]);
	return { family: 6, parts: g };
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
 * or prefix, and no IPv4 part with a leading zero, which some tools read as
 * octal.
 *
 * @param {*} s The text to parse.
 * @returns {?object} { family, parts }, or null when `s` is not an address.
 */
export function parse(s) {
	if (type(s) != "string" || length(s) == 0 || length(s) > MAX_ADDR_LEN)
		return null;

	let a = _parts(s);
	if (a && a.family == 6 && _is_mapped(a.parts)) return { family: 4, parts: _mapped_ipv4(a.parts) };
	return a;
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

	// The prefix length: one to three decimal digits after the only "/".
	// Checked digit by digit, not with an anchored regex, whose "$" some C
	// libraries let match before a trailing newline.
	let prefix = null;
	let halves = split(s, "/");
	if (length(halves) > 2) return null;
	if (length(halves) == 2) {
		let p = halves[1];
		if (length(p) < 1 || length(p) > 3) return null;
		for (let i = 0; i < length(p); i++)
			if (ord(p, i) < 48 || ord(p, i) > 57) return null;
		s = halves[0];
		prefix = int(p);
	}

	if (length(s) == 0 || length(s) > MAX_ADDR_LEN) return null;

	let a = _parts(s);
	if (!a) return null;
	let width = (a.family == 4) ? 32 : 128;
	if (prefix == null) prefix = width;
	if (prefix > width) return null;
	if (a.family == 6 && _is_mapped(a.parts) && prefix >= 96)
		return { family: 4, parts: _mapped_ipv4(a.parts), prefix: prefix - 96 };
	return { ...a, prefix };
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
