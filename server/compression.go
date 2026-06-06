package server

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// CompressionReader wraps an io.ReadCloser and optionally decompresses zstd data on read.
type CompressionReader struct {
	reader       io.ReadCloser
	decompressor *zstd.Decoder
	isCompressed bool
}

// NewCompressionReader creates a reader that decompresses zstd data when isCompressed is true.
func NewCompressionReader(reader io.ReadCloser, isCompressed bool) (*CompressionReader, error) {
	cr := &CompressionReader{
		reader:       reader,
		isCompressed: isCompressed,
	}

	if isCompressed {
		var err error
		cr.decompressor, err = zstd.NewReader(reader)
		if err != nil {
			_ = reader.Close()
			return nil, err
		}
	}

	return cr, nil
}

func (cr *CompressionReader) Read(p []byte) (int, error) {
	if cr.isCompressed && cr.decompressor != nil {
		return cr.decompressor.Read(p)
	}
	return cr.reader.Read(p)
}

// Close closes the underlying reader and decompressor if present.
func (cr *CompressionReader) Close() error {
	if cr.decompressor != nil {
		cr.decompressor.Close()
	}
	return cr.reader.Close()
}

// CompressStream compresses data from reader into writer using zstd and returns bytes written.
func CompressStream(writer io.Writer, reader io.Reader) (int64, error) {
	encoder, err := zstd.NewWriter(writer)
	if err != nil {
		return 0, err
	}
	defer func() { _ = encoder.Close() }()

	written, err := io.Copy(encoder, reader)
	return written, err
}
