package server

import (
	"time"

	. "gopkg.in/check.v1"
)

var (
	_ = Suite(&suiteUtils{})
)

type suiteUtils struct{}

func (s *suiteUtils) TestFormatNumber(c *C) {
	result := formatNumber("", uint64(1024))
	c.Assert(result, Equals, "1,024.00")

	result = formatNumber("", uint64(1048576))
	c.Assert(result, Equals, "1,048,576.00")
}

func (s *suiteUtils) TestIPAddrFromRemoteAddr(c *C) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:58292", "::1"},
		{"127.0.0.1:3000", "127.0.0.1"},
		{"localhost", "localhost"},
		{"192.168.1.1", "192.168.1.1"},
	}

	for _, test := range tests {
		result := ipAddrFromRemoteAddr(test.input)
		c.Assert(result, Equals, test.expected)
	}
}

func (s *suiteUtils) TestFormatSize(c *C) {
	tests := []struct {
		size     int64
		expected string
	}{
		{1024, "1 KB"},
		{1048576, "1 MB"},
		{1073741824, "1 GB"},
		{512, "512 B"},
	}

	for _, test := range tests {
		result := formatSize(test.size)
		c.Assert(result, Equals, test.expected, Commentf("size=%d", test.size))
	}
}

func (s *suiteUtils) TestFormatDurationDays(c *C) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{24 * time.Hour, "1 day"},
		{48 * time.Hour, "2 days"},
		{0, "0 days"},
		{72 * time.Hour, "3 days"},
	}

	for _, test := range tests {
		result := formatDurationDays(test.duration)
		c.Assert(result, Equals, test.expected)
	}
}
