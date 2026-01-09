package server

import (
	"bytes"
	"io"

	"github.com/klauspost/compress/zstd"
)

type CompressionReader struct {
	reader       io.ReadCloser
	decompressor *zstd.Decoder
	isCompressed bool
}

func NewCompressionReader(reader io.ReadCloser, isCompressed bool) (*CompressionReader, error) {
	cr := &CompressionReader{
		reader:       reader,
		isCompressed: isCompressed,
	}

	if isCompressed {
		var err error
		cr.decompressor, err = zstd.NewReader(reader)
		if err != nil {
			reader.Close()
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

func (cr *CompressionReader) Close() error {
	if cr.decompressor != nil {
		cr.decompressor.Close()
	}
	return cr.reader.Close()
}

func CompressStream(writer io.Writer, reader io.Reader) (int64, error) {
	encoder, err := zstd.NewWriter(writer)
	if err != nil {
		return 0, err
	}
	defer encoder.Close()

	written, err := io.Copy(encoder, reader)
	return written, err
}

func CompressBuffer(data []byte) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	encoder, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, err
	}

	_, err = encoder.Write(data)
	if err != nil {
		encoder.Close()
		return nil, err
	}

	err = encoder.Close()
	if err != nil {
		return nil, err
	}

	return &buf, nil
}
