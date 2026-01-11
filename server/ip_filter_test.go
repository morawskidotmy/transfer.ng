package server

import (
	"net"

	. "gopkg.in/check.v1"
)

var (
	_ = Suite(&suiteIPFilter{})
)

type suiteIPFilter struct {
	whitelist *net.IPNet
	blacklist *net.IPNet
}

func (s *suiteIPFilter) SetUpTest(c *C) {
	var err error
	_, s.whitelist, err = net.ParseCIDR("192.168.0.0/16")
	c.Assert(err, IsNil)
	_, s.blacklist, err = net.ParseCIDR("10.0.0.0/8")
	c.Assert(err, IsNil)
}

func (s *suiteIPFilter) TestWhitelistAllows(c *C) {
	c.Assert(s.whitelist.Contains(net.ParseIP("192.168.1.1")), Equals, true)
}

func (s *suiteIPFilter) TestWhitelistDenies(c *C) {
	c.Assert(s.whitelist.Contains(net.ParseIP("10.0.0.1")), Equals, false)
}

func (s *suiteIPFilter) TestBlacklistDenies(c *C) {
	c.Assert(s.blacklist.Contains(net.ParseIP("10.0.0.1")), Equals, true)
}

func (s *suiteIPFilter) TestBlacklistAllows(c *C) {
	c.Assert(s.blacklist.Contains(net.ParseIP("192.168.1.1")), Equals, false)
}

var (
	_ = Suite(&suiteIPFilterLogic{})
)

type suiteIPFilterLogic struct{}

func (s *suiteIPFilterLogic) TestNewIPFilter(c *C) {
	opts := &IPFilterOptions{
		AllowedIPs:     []string{"192.168.1.1"},
		BlockedIPs:     []string{"10.0.0.1"},
		BlockByDefault: true,
	}
	f := newIPFilter(opts)
	c.Assert(f, NotNil)
	c.Assert(f.defaultAllowed, Equals, false)
}

func (s *suiteIPFilterLogic) TestAllowedIP(c *C) {
	opts := &IPFilterOptions{
		AllowedIPs:     []string{"192.168.1.1"},
		BlockByDefault: true,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("192.168.1.1"), Equals, true)
	c.Assert(f.Allowed("192.168.1.2"), Equals, false)
}

func (s *suiteIPFilterLogic) TestBlockedIP(c *C) {
	opts := &IPFilterOptions{
		BlockedIPs:     []string{"10.0.0.1"},
		BlockByDefault: false,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("10.0.0.1"), Equals, false)
	c.Assert(f.Allowed("10.0.0.2"), Equals, true)
	c.Assert(f.Blocked("10.0.0.1"), Equals, true)
}

func (s *suiteIPFilterLogic) TestSubnetAllowed(c *C) {
	opts := &IPFilterOptions{
		AllowedIPs:     []string{"192.168.0.0/16"},
		BlockByDefault: true,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("192.168.1.1"), Equals, true)
	c.Assert(f.Allowed("192.168.255.255"), Equals, true)
	c.Assert(f.Allowed("10.0.0.1"), Equals, false)
}

func (s *suiteIPFilterLogic) TestSubnetBlocked(c *C) {
	opts := &IPFilterOptions{
		BlockedIPs:     []string{"10.0.0.0/8"},
		BlockByDefault: false,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("10.0.0.1"), Equals, false)
	c.Assert(f.Allowed("10.255.255.255"), Equals, false)
	c.Assert(f.Allowed("192.168.1.1"), Equals, true)
}

func (s *suiteIPFilterLogic) TestToggleDefault(c *C) {
	opts := &IPFilterOptions{
		BlockByDefault: true,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("192.168.1.1"), Equals, false)
	f.ToggleDefault(true)
	c.Assert(f.Allowed("192.168.1.1"), Equals, true)
}

func (s *suiteIPFilterLogic) TestToggleIP(c *C) {
	opts := &IPFilterOptions{
		BlockByDefault: true,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("192.168.1.1"), Equals, false)
	f.AllowIP("192.168.1.1")
	c.Assert(f.Allowed("192.168.1.1"), Equals, true)
	f.BlockIP("192.168.1.1")
	c.Assert(f.Allowed("192.168.1.1"), Equals, false)
}

func (s *suiteIPFilterLogic) TestInvalidIP(c *C) {
	opts := &IPFilterOptions{
		BlockByDefault: false,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("invalid"), Equals, false)
	c.Assert(f.NetAllowed(nil), Equals, false)
}

func (s *suiteIPFilterLogic) TestIPv6(c *C) {
	opts := &IPFilterOptions{
		AllowedIPs:     []string{"::1"},
		BlockByDefault: true,
	}
	f := newIPFilter(opts)

	c.Assert(f.Allowed("::1"), Equals, true)
	c.Assert(f.Allowed("::2"), Equals, false)
}

func (s *suiteIPFilterLogic) TestNetBlocked(c *C) {
	opts := &IPFilterOptions{
		BlockedIPs: []string{"10.0.0.1"},
	}
	f := newIPFilter(opts)

	c.Assert(f.NetBlocked(net.ParseIP("10.0.0.1")), Equals, true)
	c.Assert(f.NetBlocked(net.ParseIP("192.168.1.1")), Equals, false)
}
