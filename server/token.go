package server

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"math"
	"strings"
)

const (
	symbols = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func token(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)

	symbolsLen := uint32(len(symbols))
	maxValid := (math.MaxUint32 / symbolsLen) * symbolsLen

	buf := make([]byte, length*4)
	if _, err := cryptoRand.Read(buf); err != nil {
		return "", err
	}

	for i := 0; i < length; i++ {
		val := binary.BigEndian.Uint32(buf[i*4 : i*4+4])
		for val >= maxValid {
			if _, err := cryptoRand.Read(buf[i*4 : i*4+4]); err != nil {
				return "", err
			}
			val = binary.BigEndian.Uint32(buf[i*4 : i*4+4])
		}
		builder.WriteByte(symbols[val%symbolsLen])
	}

	return builder.String(), nil
}
