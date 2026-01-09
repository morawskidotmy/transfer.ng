package server

import (
	"regexp"

	. "gopkg.in/check.v1"
)

var (
	_ = Suite(&suiteToken{})
)

type suiteToken struct{}

func (s *suiteToken) TestTokenGeneration(c *C) {
	t, err := token(6)
	c.Assert(err, IsNil)
	c.Assert(len(t), Equals, 6)

	// Verify it only contains valid characters
	validChars := regexp.MustCompile("^[0-9a-zA-Z]+$")
	c.Assert(validChars.MatchString(t), Equals, true)
}

func (s *suiteToken) TestTokenUniqueness(c *C) {
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		t, err := token(8)
		c.Assert(err, IsNil)
		c.Assert(tokens[t], Equals, false, Commentf("Generated duplicate token: %s", t))
		tokens[t] = true
	}
}

func (s *suiteToken) TestTokenLengthVariation(c *C) {
	for length := 1; length <= 20; length++ {
		t, err := token(length)
		c.Assert(err, IsNil)
		c.Assert(len(t), Equals, length)
	}
}

func (s *suiteToken) TestTokenSymbolSet(c *C) {
	for i := 0; i < 50; i++ {
		t, err := token(20)
		c.Assert(err, IsNil)

		for _, ch := range t {
			c.Assert(string(ch), Matches, "[0-9a-zA-Z]")
		}
	}
}
