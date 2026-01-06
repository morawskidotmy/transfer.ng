
package server

import (
	cryptoRand "crypto/rand"
	"strings"
)

const (
	SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func token(length int) string {
	var builder strings.Builder
	builder.Grow(length)
	
	b := make([]byte, length)
	if _, err := cryptoRand.Read(b); err != nil {
		panic("failed to read random bytes for token generation")
	}
	
	for i := 0; i < length; i++ {
		builder.WriteByte(SYMBOLS[b[i]%byte(len(SYMBOLS))])
	}

	return builder.String()
}
