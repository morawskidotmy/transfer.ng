package server

import (
	"math"
	"net/http"
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

func (s *suiteUtils) TestFormatNumberWithFormat(c *C) {
	result := formatNumber("#,##0.###", uint64(1024))
	c.Assert(result, Equals, "1,024.000")

	result = formatNumber("0.00", uint64(42))
	c.Assert(result, Equals, "42.00")
}

func (s *suiteUtils) TestRenderFloatSpecialCases(c *C) {
	c.Assert(handleSpecialCases(math.NaN()), Equals, "NaN")
	c.Assert(handleSpecialCases(1.0), Equals, "")
	c.Assert(handleSpecialCases(0.0), Equals, "")
}

func (s *suiteUtils) TestGenerateSignPart(c *C) {
	sign, val := generateSignPart(5.0, "+", "-")
	c.Assert(sign, Equals, "+")
	c.Assert(val, Equals, 5.0)

	sign, val = generateSignPart(-5.0, "+", "-")
	c.Assert(sign, Equals, "-")
	c.Assert(val, Equals, 5.0)

	sign, val = generateSignPart(0.0, "+", "-")
	c.Assert(sign, Equals, "")
	c.Assert(val, Equals, 0.0)
}

func (s *suiteUtils) TestParseFormatString(c *C) {
	precision, decimal, thousand, positive, negative := parseFormatString("")
	c.Assert(precision, Equals, 2)
	c.Assert(decimal, Equals, ".")
	c.Assert(thousand, Equals, ",")
	c.Assert(positive, Equals, "")
	c.Assert(negative, Equals, "-")

	precision, decimal, thousand, _, _ = parseFormatString("#,##0.###")
	c.Assert(precision, Equals, 3)
	c.Assert(decimal, Equals, ".")
	c.Assert(thousand, Equals, ",")
}

func (s *suiteUtils) TestAddThousandSeparator(c *C) {
	c.Assert(addThousandSeparator("1000000", ","), Equals, "1,000,000")
	c.Assert(addThousandSeparator("100", ","), Equals, "100")
	c.Assert(addThousandSeparator("1000", "."), Equals, "1.000")
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

func (s *suiteUtils) TestAcceptsHTML(c *C) {
	h := http.Header{}
	h.Set("Accept", "text/html,application/xhtml+xml")
	c.Assert(acceptsHTML(h), Equals, true)

	h2 := http.Header{}
	h2.Set("Accept", "application/json")
	c.Assert(acceptsHTML(h2), Equals, false)

	h2 = http.Header{}
	h2.Set("Accept", "*/*")
	c.Assert(acceptsHTML(h2), Equals, false)

	h3 := http.Header{}
	c.Assert(acceptsHTML(h3), Equals, false)
}

func (s *suiteUtils) TestFormatSize(c *C) {
	tests := []struct {
		size     int64
		expected string
	}{
		{0, "0 B"},
		{-1, "0 B"},
		{1, "1 B"},
		{1024, "1 KB"},
		{1048576, "1 MB"},
		{1073741824, "1 GB"},
		{512, "512 B"},
		{1099511627776, "1 TB"},
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
