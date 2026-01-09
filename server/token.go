package server

import (
	cryptoRand "crypto/rand"
	"strings"
)

const (
	SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func token(length int) (string, error) {
	var builder strings.Builder
	builder.Grow(length)

	b := make([]byte, length)
	if _, err := cryptoRand.Read(b); err != nil {
		return "", err
	}

	for i := 0; i < length; i++ {
		builder.WriteByte(SYMBOLS[b[i]%byte(len(SYMBOLS))])
	}

	return builder.String(), nil
}
