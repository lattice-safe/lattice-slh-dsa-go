package slhdsa_test

import (
	"crypto/rand"
	"testing"

	"github.com/lattice-safe/lattice-slh-dsa-go"
)

func BenchmarkGenerateKey_Shake128f(b *testing.B) {
	mode := slhdsa.SlhDsaShake128f
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		slhdsa.GenerateKey(mode)
	}
}

func BenchmarkSign_Shake128f(b *testing.B) {
	mode := slhdsa.SlhDsaShake128f
	sk, _, _ := slhdsa.GenerateKey(mode)
	msg := make([]byte, 32)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(msg)
	}
}

func BenchmarkVerify_Shake128f(b *testing.B) {
	mode := slhdsa.SlhDsaShake128f
	sk, pk, _ := slhdsa.GenerateKey(mode)
	msg := make([]byte, 32)
	rand.Read(msg)
	sig, _ := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(msg, sig)
	}
}

func BenchmarkSign_Sha2_128f(b *testing.B) {
	mode := slhdsa.SlhDsaSha2_128f
	sk, _, _ := slhdsa.GenerateKey(mode)
	msg := make([]byte, 32)
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(msg)
	}
}

func BenchmarkVerify_Sha2_128f(b *testing.B) {
	mode := slhdsa.SlhDsaSha2_128f
	sk, pk, _ := slhdsa.GenerateKey(mode)
	msg := make([]byte, 32)
	rand.Read(msg)
	sig, _ := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(msg, sig)
	}
}
