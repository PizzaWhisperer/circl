package internal

import (
	cRand "crypto/rand"
	"testing"
)

func BenchmarkDerive(b *testing.B) {
	rand := cRand.Reader
	var rho [32]byte
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		rand.Read(rho[:])
		A := new(Mat)
		b.StartTimer()
		A.Derive(&rho)
	}
}

func BenchmarkDeriveOverhead(b *testing.B) {
	rand := cRand.Reader
	var rho [32]byte
	for n := 0; n < b.N; n++ {
		rand.Read(rho[:])
	}
}
