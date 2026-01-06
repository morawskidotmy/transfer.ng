
package server

import (
	"strings"
)

const (
	// SYMBOLS characters used for short-urls
	SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// generate a token
func token(length int) string {
	var builder strings.Builder
	builder.Grow(length)
	
	for i := 0; i < length; i++ {
		x := theRand.Intn(len(SYMBOLS) - 1)
		builder.WriteByte(SYMBOLS[x])
	}

	return builder.String()
}
