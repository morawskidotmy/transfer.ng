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
