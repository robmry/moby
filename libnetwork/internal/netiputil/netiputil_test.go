package netiputil

import (
	"net"
	"net/netip"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestLastAddr(t *testing.T) {
	testcases := []struct {
		p    netip.Prefix
		want netip.Addr
	}{
		{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParseAddr("10.0.0.255")},
		{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParseAddr("10.255.255.255")},
		{netip.MustParsePrefix("fd00::/64"), netip.MustParseAddr("fd00::ffff:ffff:ffff:ffff")},
		{netip.MustParsePrefix("fd00::/16"), netip.MustParseAddr("fd00:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{netip.MustParsePrefix("ffff::/16"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}

	for _, tc := range testcases {
		last := LastAddr(tc.p)
		assert.Check(t, last == tc.want, "LastAddr(%q) = %s; want: %s", tc.p, last, tc.want)
	}
}

func TestPrefixAfter(t *testing.T) {
	testcases := []struct {
		prev netip.Prefix
		sz   int
		want netip.Prefix
	}{
		{netip.MustParsePrefix("10.0.10.0/24"), 24, netip.MustParsePrefix("10.0.11.0/24")},
		{netip.MustParsePrefix("10.0.10.0/24"), 16, netip.MustParsePrefix("10.1.0.0/16")},
		{netip.MustParsePrefix("10.10.0.0/16"), 24, netip.MustParsePrefix("10.11.0.0/24")},
		{netip.MustParsePrefix("2001:db8:feed:cafe:b000:dead::/96"), 16, netip.MustParsePrefix("2002::/16")},
		{netip.MustParsePrefix("ffff::/16"), 16, netip.Prefix{}},
		{netip.MustParsePrefix("2001:db8:1::/48"), 64, netip.MustParsePrefix("2001:db8:2::/64")},
	}

	for _, tc := range testcases {
		next := PrefixAfter(tc.prev, tc.sz)
		assert.Check(t, next == tc.want, "PrefixAfter(%q, %d) = %s; want: %s", tc.prev, tc.sz, next, tc.want)
	}
}

func TestToPrefix(t *testing.T) {
	testcases := []struct {
		prefix string
	}{
		{prefix: "172.17.0.0/16"},
		{prefix: "172.17.0.3/16"}, // host bits not masked
		{prefix: "fdff:3fde:9a11::/64"},
		{prefix: "fdff:3fde:9a11::2/64"},
		{prefix: "::ffff:172.17.0.3/120"},
	}
	for _, tc := range testcases {
		t.Run(tc.prefix, func(t *testing.T) {
			ip, ipnet, err := net.ParseCIDR(tc.prefix)
			assert.NilError(t, err)
			ipnet.IP = ip // Keep host bits in ipnet if set in tc.prefix.

			p, ok := ToPrefix(ipnet)
			assert.Check(t, ok)
			assert.Check(t, is.Equal(p.String(), tc.prefix))
		})
	}
}
