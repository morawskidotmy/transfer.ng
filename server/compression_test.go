package server

import (
	"bytes"
	"io"

	. "gopkg.in/check.v1"
)

var (
	_ = Suite(&suiteCompression{})
)

type suiteCompression struct{}

func (s *suiteCompression) TestCompressionReader(c *C) {
	data := []byte("test data")
	buf := bytes.NewReader(data)
	
	rc, err := NewCompressionReader(io.NopCloser(buf), false)
	c.Assert(err, IsNil)
	
	result, err := io.ReadAll(rc)
	c.Assert(err, IsNil)
	c.Assert(result, DeepEquals, data)
	c.Assert(rc.Close(), IsNil)
}

func (s *suiteCompression) TestCompressBuffer(c *C) {
	data := []byte("test data for compression")
	
	compressed, err := CompressBuffer(data)
	c.Assert(err, IsNil)
	c.Assert(compressed, NotNil)
	c.Assert(compressed.Len() > 0, Equals, true)
}

func (s *suiteCompression) TestCompressStream(c *C) {
	data := []byte("test stream data")
	reader := bytes.NewReader(data)
	writer := &bytes.Buffer{}
	
	written, err := CompressStream(writer, reader)
	c.Assert(err, IsNil)
	c.Assert(written, Equals, int64(len(data)))
	c.Assert(writer.Len() > 0, Equals, true)
}
