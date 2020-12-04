package dilithium

import (
	"fmt"
	"testing"

	cRand "crypto/rand"
)

func BenchmarkKeyGen(b *testing.B) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		mode.GenerateKey(rand)
	}
}

func BenchmarkSign(b *testing.B) {
	mode := ModeByName("Dilithium3")
	var msg [59]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		_, sk, _ := mode.GenerateKey(rand)
		rand.Read(msg[:])
		b.StartTimer()
		mode.Sign(sk, msg[:])
	}
}

func BenchmarkVerify(b *testing.B) {
	mode := ModeByName("Dilithium3")
	var msg [59]byte
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		pk, sk, _ := mode.GenerateKey(rand)
		rand.Read(msg[:])
		sig := mode.Sign(sk, msg[:])
		b.StartTimer()
		mode.Verify(pk, msg[:], sig)
	}
}

func BenchmarkPackPK(b *testing.B) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		pk, _, _ := mode.GenerateKey(rand)
		b.StartTimer()
		pk.Bytes()
	}
}

func BenchmarkUnPackPK(b *testing.B) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		pk, _, _ := mode.GenerateKey(rand)
		packedPk := pk.Bytes()
		b.StartTimer()
		mode.PublicKeyFromBytes(packedPk)
	}
}

func BenchmarkPackSK(b *testing.B) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		_, sk, _ := mode.GenerateKey(rand)
		b.StartTimer()
		sk.Bytes()
	}
}

func BenchmarkUnPackSK(b *testing.B) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		_, sk, _ := mode.GenerateKey(rand)
		packedSk := sk.Bytes()
		b.StartTimer()
		mode.PrivateKeyFromBytes(packedSk)
	}
}

func TestSize(b *testing.T) {
	mode := ModeByName("Dilithium3")
	rand := cRand.Reader
	var msg [59]byte
	pk, sk, _ := mode.GenerateKey(rand)
	rand.Read(msg[:])
	sig := mode.Sign(sk, msg[:])
	fmt.Printf("Sig len %d\n", len(sig))
	fmt.Printf("PK len %d\n", len(pk.Bytes()))
	fmt.Printf("SK len %d\n", len(sk.Bytes()))

}
