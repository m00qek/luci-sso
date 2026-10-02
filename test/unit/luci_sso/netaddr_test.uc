import { describe, it, assert } from 'utest';
import * as netaddr from 'luci_sso.netaddr';

// netaddr.uc is pure: no deps, nothing to fake.

const fmt = (a) => a ? netaddr.format(a) : null;

// ─── parse ────────────────────────────────────────────────────────────────────

describe('netaddr: parse', () => {
	it('parses dotted IPv4', () => {
		assert.match({ family: 4, parts: [ 192, 0, 2, 7 ] }, netaddr.parse('192.0.2.7'));
		assert.match('0.0.0.0', fmt(netaddr.parse('0.0.0.0')));
		assert.match('255.255.255.255', fmt(netaddr.parse('255.255.255.255')));
	});

	it('parses IPv6 in any standard form, to eight lowercase groups', () => {
		assert.match('2001:db8:0:0:0:0:0:1', fmt(netaddr.parse('2001:db8::1')));
		assert.match('2001:db8:1:2:aaaa:bbbb:cccc:dddd', fmt(netaddr.parse('2001:0DB8:0001:0002:AAAA:bbbb:cccc:dddd')));
		assert.match('0:0:0:0:0:0:0:1', fmt(netaddr.parse('::1')));
		assert.match('0:0:0:0:0:0:0:0', fmt(netaddr.parse('::')));
		assert.match('64:ff9b:0:0:0:0:c000:201', fmt(netaddr.parse('64:ff9b::192.0.2.1')), 'an IPv4 tail that is not IPv4-mapped');
	});

	it('returns an IPv4-mapped IPv6 address as the IPv4 address it carries', () => {
		assert.match({ family: 4, parts: [ 192, 0, 2, 7 ] }, netaddr.parse('::ffff:192.0.2.7'));
		assert.match('192.0.2.7', fmt(netaddr.parse('::FFFF:c000:207')));
	});

	it('refuses anything that is not a bare address', () => {
		for (let bad in [ null, '', 42, [ '1.2.3.4' ], 'localhost', '256.1.1.1', '1.2.3', '1.2.3.4.5',
		                  ' 1.2.3.4', '1.2.3.4 ', '1.2.3.4:80', '[::1]', '::1%eth0', '10.0.0.0/8',
		                  '1:2:3:4:5:6:7:8:9', '1::2::3', '12345::1', 'gggg::1', '::ffff:999.1.1.1',
		                  '1:2:3:4:5:6:7::8' ])
			assert.match(null, netaddr.parse(bad), `${bad}`);
	});

	it('refuses an IPv4 part with a leading zero, which some tools read as octal', () => {
		for (let bad in [ '010.0.0.1', '10.0.0.01', '001.2.3.4', '::ffff:10.0.0.01' ])
			assert.match(null, netaddr.parse(bad), bad);
	});

	it('refuses an address followed by a NUL byte or a newline, and anything after it', () => {
		for (let bad in [ '1.2.3.4\u0000', '1.2.3.4\u00000.0.0.0', '::1\u0000', 'fe\u000080::1', '1.2.3.4\n', '1.2.3.4\n0.0.0.0', '::1\n' ])
			assert.match(null, netaddr.parse(bad), sprintf("%J", bad));
	});
});

// ─── parse_cidr / contains ────────────────────────────────────────────────────

describe('netaddr: parse_cidr', () => {
	it('reads an address as a range of one, and a prefix up to the family\'s width', () => {
		assert.match({ family: 4, parts: [ 127, 0, 0, 1 ], prefix: 32 }, netaddr.parse_cidr('127.0.0.1'));
		assert.match({ family: 4, parts: [ 10, 0, 0, 0 ], prefix: 8 }, netaddr.parse_cidr('10.0.0.0/8'));
		assert.match(0, netaddr.parse_cidr('0.0.0.0/0').prefix);
		assert.match(128, netaddr.parse_cidr('::1').prefix);
		assert.match(32, netaddr.parse_cidr('2001:db8::/32').prefix);
		assert.match(128, netaddr.parse_cidr('::1/128').prefix);
	});

	it('reads an IPv4-mapped range of /96 or longer as IPv4', () => {
		assert.match({ family: 4, parts: [ 192, 0, 2, 1 ], prefix: 32 }, netaddr.parse_cidr('::ffff:192.0.2.1'));
		assert.match({ family: 4, parts: [ 192, 0, 2, 0 ], prefix: 24 }, netaddr.parse_cidr('::ffff:192.0.2.0/120'));
		assert.match(6, netaddr.parse_cidr('::ffff:0:0/80').family);
	});

	it('refuses a bad address, a prefix too long, a netmask, a port and a zone', () => {
		for (let bad in [ null, '', '/8', '10.0.0.0/', '10.0.0.0/33', '::/129', '10.0.0.0/255.0.0.0', '10.0.0.0/8/8',
		                  '10.0.0.0/-1', 'localhost', '1.2.3.4:80', '[::1]', 'fe80::1%eth0', ' 10.0.0.1', '10.0.0.0/08x' ])
			assert.match(null, netaddr.parse_cidr(bad), `${bad}`);
	});

	it('refuses a NUL byte or a newline anywhere, in the address or the prefix', () => {
		for (let bad in [ '10.0.0.0/8\n', '10.0.0.0/8\n0.0.0.0/0', '10.0.0.0\n/8', '127.0.0.1\n0.0.0.0/0', '10.0.0.0/8\u0000', '10.0.0.0\u0000/8', '::/0\u0000' ])
			assert.match(null, netaddr.parse_cidr(bad), sprintf("%J", bad));
	});

	it('reads a prefix of one to three digits, leading zeros included', () => {
		assert.match(8, netaddr.parse_cidr('10.0.0.0/08').prefix);
		assert.match(8, netaddr.parse_cidr('10.0.0.0/008').prefix);
		assert.match(null, netaddr.parse_cidr('10.0.0.0/0008'));
	});
});

describe('netaddr: contains', () => {
	const inside = (range, addr) => netaddr.contains(netaddr.parse_cidr(range), netaddr.parse(addr));

	it('matches an address against a range of one', () => {
		assert.match(true, inside('127.0.0.1', '127.0.0.1'));
		assert.match(false, inside('127.0.0.1', '127.0.0.2'));
		assert.match(true, inside('::1', '0:0::1'));
	});

	it('matches by prefix, including one that is not a multiple of 8 or 16', () => {
		assert.match(true, inside('10.0.0.0/8', '10.255.1.2'));
		assert.match(false, inside('10.0.0.0/8', '11.0.0.1'));
		assert.match(true, inside('172.16.0.0/12', '172.31.255.255'));
		assert.match(false, inside('172.16.0.0/12', '172.32.0.0'));
		assert.match(true, inside('10.0.0.5/24', '10.0.0.200'), 'host bits in the range are ignored');
		assert.match(true, inside('0.0.0.0/0', '198.51.100.1'));
		assert.match(true, inside('2001:db8::/32', '2001:db8:ffff::1'));
		assert.match(false, inside('2001:db8::/33', '2001:db8:8000::1'));
		assert.match(true, inside('fc00::/7', 'fdff::1'));
	});

	it('never matches across families, and an IPv4-mapped client is an IPv4 one', () => {
		assert.match(false, inside('::/0', '192.0.2.1'));
		assert.match(false, inside('0.0.0.0/0', '::1'));
		assert.match(true, inside('192.0.2.0/24', '::ffff:192.0.2.1'));
		assert.match(true, inside('::ffff:192.0.2.0/120', '192.0.2.9'));
	});

	it('is false for a missing range or address', () => {
		assert.match(false, netaddr.contains(null, netaddr.parse('1.2.3.4')));
		assert.match(false, netaddr.contains(netaddr.parse_cidr('1.2.3.4'), null));
	});
});
