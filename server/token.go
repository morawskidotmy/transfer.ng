package server

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"strings"
)

const (
	SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func token(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)

	symbolsLen := uint32(len(SYMBOLS))
	maxValid := (0xFFFFFFFF / symbolsLen) * symbolsLen

	for i := 0; i < length; i++ {
		var val uint32
		for {
			b := make([]byte, 4)
			if _, err := cryptoRand.Read(b); err != nil {
				return "", err
			}
			val = binary.BigEndian.Uint32(b)
			if val < maxValid {
				break
			}
		}
		builder.WriteByte(SYMBOLS[val%symbolsLen])
	}

	return builder.String(), nil
}
