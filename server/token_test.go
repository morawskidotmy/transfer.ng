package server

import (
	"strings"
	"testing"
)

func TestTokenLength(t *testing.T) {
	for _, length := range []int{1, 5, 10, 20, 100} {
		tok, err := token(length)
		if err != nil {
			t.Fatalf("token(%d) returned error: %v", length, err)
		}
		if len(tok) != length {
			t.Errorf("token(%d) returned length %d", length, len(tok))
		}
	}
}

func TestTokenCharacters(t *testing.T) {
	tok, err := token(1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tok {
		if !strings.ContainsRune(SYMBOLS, c) {
			t.Errorf("token contains invalid character: %c", c)
		}
	}
}

func TestTokenUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, err := token(10)
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Errorf("duplicate token generated: %s", tok)
		}
		seen[tok] = true
	}
}

func BenchmarkTokenConcat(b *testing.B) {
	for i := 0; i < b.N; i++ {
		t1, _ := token(5)
		t2, _ := token(5)
		_ = t1 + t2
	}
}

func BenchmarkTokenLonger(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = token(10)
	}
}
