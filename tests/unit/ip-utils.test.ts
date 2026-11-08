/**
 * Unit tests for IP address utility functions.
 *
 * Tests cover IPv4/IPv6 parsing, CIDR matching, and public/private
 * range detection — all pure functions with no I/O or network access.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseIp, parseCIDR, CIDR, isIPInNonPublicRange, ipBufferToString } from '../../build/utils/ip.js';

// ---------------------------------------------------------------------------
// parseIp
// ---------------------------------------------------------------------------

describe('parseIp: IPv4', () => {
    it('parses a standard IPv4 address into a 4-byte buffer', () => {
        const buf = parseIp('192.168.1.1');
        assert.equal(buf.byteLength, 4);
    });

    it('encodes each octet at the correct byte position', () => {
        const buf = parseIp('10.20.30.40');
        assert.equal(buf[0], 10);
        assert.equal(buf[1], 20);
        assert.equal(buf[2], 30);
        assert.equal(buf[3], 40);
    });

    it('handles 0.0.0.0', () => {
        const buf = parseIp('0.0.0.0');
        assert.deepEqual([...buf], [0, 0, 0, 0]);
    });

    it('handles 255.255.255.255', () => {
        const buf = parseIp('255.255.255.255');
        assert.deepEqual([...buf], [255, 255, 255, 255]);
    });

    it('handles loopback 127.0.0.1', () => {
        const buf = parseIp('127.0.0.1');
        assert.deepEqual([...buf], [127, 0, 0, 1]);
    });
});

describe('parseIp: IPv4 embedded in IPv6', () => {
    it('keeps the ffff prefix of an IPv4-mapped address', () => {
        const buf = parseIp('::ffff:127.0.0.1');
        assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
    });

    it('parses the uncompressed mapped form', () => {
        const buf = parseIp('0:0:0:0:0:ffff:192.0.2.1');
        assert.equal(buf.toString('hex'), '00000000000000000000ffffc0000201');
    });

    it('parses an uppercase mapped prefix', () => {
        const buf = parseIp('::FFFF:192.168.0.1');
        assert.equal(buf.toString('hex'), '00000000000000000000ffffc0a80001');
    });

    it('parses an IPv4-compatible address', () => {
        const buf = parseIp('::192.168.1.1');
        assert.equal(buf.toString('hex'), '000000000000000000000000c0a80101');
    });

    it('preserves hextets that precede a compressed dotted tail', () => {
        const buf = parseIp('64:ff9b::192.0.2.1');
        assert.equal(buf.toString('hex'), '0064ff9b0000000000000000c0000201');
    });

    it('preserves a hextet immediately before the dotted tail', () => {
        const buf = parseIp('2001:db8:85a3::8a2e:192.0.2.1');
        assert.equal(buf.toString('hex'), '20010db885a3000000008a2ec0000201');
    });
});

describe('parseIp: IPv6', () => {
    it('parses the loopback address ::1 into a 16-byte buffer', () => {
        const buf = parseIp('::1');
        assert.equal(buf.byteLength, 16);
        // Last byte is 1, rest are 0
        assert.equal(buf[15], 1);
        for (let i = 0; i < 15; i++) assert.equal(buf[i], 0);
    });

    it('parses :: (all-zeros) correctly', () => {
        const buf = parseIp('::');
        assert.equal(buf.byteLength, 16);
        for (let i = 0; i < 16; i++) assert.equal(buf[i], 0);
    });

    it('parses a full IPv6 address', () => {
        const buf = parseIp('2001:db8::1');
        assert.equal(buf.byteLength, 16);
        assert.equal(buf[0], 0x20);
        assert.equal(buf[1], 0x01);
    });
});

describe('parseIp: errors', () => {
    it('throws for an invalid IP string', () => {
        assert.throws(() => parseIp('not-an-ip'), /Invalid IP address/);
    });

    it('throws for an empty string', () => {
        assert.throws(() => parseIp(''), /Invalid IP address/);
    });

    it('throws for a hostname', () => {
        assert.throws(() => parseIp('example.com'), /Invalid IP address/);
    });
});

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

describe('CIDR: IPv4', () => {
    it('family property returns 4 for an IPv4 CIDR', () => {
        assert.equal(new CIDR('10.0.0.0/8').family, 4);
    });

    it('matches an IP inside the range', () => {
        const cidr = new CIDR('10.0.0.0/8');
        assert.ok(cidr.test('10.0.1.5'));
        assert.ok(cidr.test('10.255.255.255'));
    });

    it('rejects an IP outside the range', () => {
        const cidr = new CIDR('10.0.0.0/8');
        assert.ok(!cidr.test('11.0.0.1'));
        assert.ok(!cidr.test('192.168.1.1'));
    });

    it('matches the exact network address', () => {
        assert.ok(new CIDR('192.168.0.0/16').test('192.168.0.0'));
    });

    it('handles /32 (host route)', () => {
        const cidr = new CIDR('1.2.3.4/32');
        assert.ok(cidr.test('1.2.3.4'));
        assert.ok(!cidr.test('1.2.3.5'));
    });

    it('handles /24 (class C block)', () => {
        const cidr = new CIDR('192.168.1.0/24');
        assert.ok(cidr.test('192.168.1.100'));
        assert.ok(!cidr.test('192.168.2.1'));
    });

    it('returns false when testing an IPv6 address against an IPv4 CIDR', () => {
        const cidr = new CIDR('10.0.0.0/8');
        assert.ok(!cidr.test('::1'));
    });

    it('toString returns the original CIDR string', () => {
        assert.equal(new CIDR('10.0.0.0/8').toString(), '10.0.0.0/8');
    });
});

describe('CIDR: IPv6', () => {
    it('family property returns 6 for an IPv6 CIDR', () => {
        assert.equal(new CIDR('fc00::/7').family, 6);
    });

    it('matches an IPv6 address inside the range', () => {
        const cidr = new CIDR('fc00::/7');
        assert.ok(cidr.test('fc00::1'));
        assert.ok(cidr.test('fd00::1'));
    });

    it('rejects an IPv6 address outside the range', () => {
        const cidr = new CIDR('fc00::/7');
        assert.ok(!cidr.test('2001:db8::1'));
    });

    it('matches the exact loopback ::1/128', () => {
        const cidr = new CIDR('::1/128');
        assert.ok(cidr.test('::1'));
        assert.ok(!cidr.test('::2'));
    });
});

// ---------------------------------------------------------------------------
// isIPInNonPublicRange
// ---------------------------------------------------------------------------

describe('isIPInNonPublicRange: private IPv4 addresses', () => {
    it('returns true for RFC1918 10.0.0.0/8 range', () => {
        assert.ok(isIPInNonPublicRange('10.0.0.1'));
        assert.ok(isIPInNonPublicRange('10.255.255.254'));
    });

    it('returns true for RFC1918 172.16.0.0/12 range', () => {
        assert.ok(isIPInNonPublicRange('172.16.0.1'));
        assert.ok(isIPInNonPublicRange('172.31.255.254'));
    });

    it('returns true for RFC1918 192.168.0.0/16 range', () => {
        assert.ok(isIPInNonPublicRange('192.168.1.1'));
    });

    it('returns true for loopback 127.0.0.1', () => {
        assert.ok(isIPInNonPublicRange('127.0.0.1'));
    });

    it('returns true for link-local 169.254.x.x', () => {
        assert.ok(isIPInNonPublicRange('169.254.0.1'));
    });
});

describe('isIPInNonPublicRange: public IPv4 addresses', () => {
    it('returns false for a well-known public DNS (8.8.8.8)', () => {
        assert.ok(!isIPInNonPublicRange('8.8.8.8'));
    });

    it('returns false for Cloudflare DNS (1.1.1.1)', () => {
        assert.ok(!isIPInNonPublicRange('1.1.1.1'));
    });

    it('returns false for a public address (93.184.216.34)', () => {
        assert.ok(!isIPInNonPublicRange('93.184.216.34'));
    });
});

describe('isIPInNonPublicRange: IPv6', () => {
    it('returns true for the IPv6 loopback ::1', () => {
        assert.ok(isIPInNonPublicRange('::1'));
    });

    it('returns true for unique-local fc00::/7 range', () => {
        assert.ok(isIPInNonPublicRange('fc00::1'));
        assert.ok(isIPInNonPublicRange('fd00::1'));
    });

    it('returns false for Google DNS 2001:4860:4860::8888', () => {
        assert.ok(!isIPInNonPublicRange('2001:4860:4860::8888'));
    });
});

describe('isIPInNonPublicRange: IPv4 embedded in IPv6', () => {
    it('treats IPv4-mapped private and loopback addresses as non-public', () => {
        assert.ok(isIPInNonPublicRange('::ffff:10.0.0.1'));
        assert.ok(isIPInNonPublicRange('::ffff:172.16.0.1'));
        assert.ok(isIPInNonPublicRange('::ffff:192.168.1.1'));
        assert.ok(isIPInNonPublicRange('::ffff:127.0.0.1'));
        assert.ok(isIPInNonPublicRange('::ffff:169.254.169.254'));
        assert.ok(isIPInNonPublicRange('0:0:0:0:0:ffff:10.1.2.3'));
    });

    it('treats IPv4-mapped public addresses as public', () => {
        assert.ok(!isIPInNonPublicRange('::ffff:8.8.8.8'));
        assert.ok(!isIPInNonPublicRange('::ffff:1.1.1.1'));
    });

    it('applies the IPv4 ranges to IPv4-compatible addresses', () => {
        assert.ok(isIPInNonPublicRange('::10.1.2.3'));
        assert.ok(isIPInNonPublicRange('::192.168.0.1'));
        assert.ok(!isIPInNonPublicRange('::8.8.8.8'));
    });

    it('still classifies native IPv6 loopback and unspecified addresses', () => {
        assert.ok(isIPInNonPublicRange('::1'));
        assert.ok(isIPInNonPublicRange('::'));
    });
});

// ---------------------------------------------------------------------------
// ipBufferToString
// ---------------------------------------------------------------------------

describe('ipBufferToString: IPv4', () => {
    it('reconstructs a dotted-decimal IPv4 address from a 4-byte buffer', () => {
        const buf = parseIp('192.168.1.100');
        assert.equal(ipBufferToString(buf), '192.168.1.100');
    });

    it('handles all-zeros 0.0.0.0', () => {
        assert.equal(ipBufferToString(parseIp('0.0.0.0')), '0.0.0.0');
    });

    it('handles all-ones 255.255.255.255', () => {
        assert.equal(ipBufferToString(parseIp('255.255.255.255')), '255.255.255.255');
    });
});

describe('ipBufferToString: errors', () => {
    it('throws for a buffer that is not 4 or 16 bytes', () => {
        assert.throws(() => ipBufferToString(Buffer.alloc(8)), /Invalid buffer length/);
    });
});

// ---------------------------------------------------------------------------
// parseCIDR (low-level)
// ---------------------------------------------------------------------------

describe('parseCIDR', () => {
    it('returns a [network, mask] tuple where both buffers have the same length', () => {
        const [net, mask] = parseCIDR('10.0.0.0/8');
        assert.equal(net.byteLength, mask.byteLength);
        assert.equal(net.byteLength, 4);
    });

    it('network address has host bits zeroed out', () => {
        const [net] = parseCIDR('192.168.1.100/24');
        // /24 → last byte should be zero
        assert.equal(net[3], 0);
    });

    it('mask has the correct prefix bits set', () => {
        const [, mask] = parseCIDR('10.0.0.0/8');
        assert.equal(mask[0], 0xff);
        assert.equal(mask[1], 0x00);
    });
});
