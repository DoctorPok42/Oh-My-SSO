package service

import "testing"

func BenchmarkHashPassword(b *testing.B) {
	for b.Loop() {
		if _, err := HashPassword("correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
	}
}
