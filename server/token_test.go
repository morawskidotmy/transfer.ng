package server

import "testing"

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
