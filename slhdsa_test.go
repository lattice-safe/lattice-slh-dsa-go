package slhdsa

import (
	"bytes"
	"testing"
)

func TestKeygenSignVerifyShake128f(t *testing.T) {
	mode := SlhDsaShake128f
	seed := make([]byte, mode.SeedBytes())
	for i := range seed {
		seed[i] = 42
	}

	sk, pk, err := GenerateKeyFromSeed(mode, seed)
	if err != nil {
		t.Fatalf("GenerateKeyFromSeed failed: %v", err)
	}

	if len(pk.Pk) != mode.PkBytes() {
		t.Errorf("expected pk len %d, got %d", mode.PkBytes(), len(pk.Pk))
	}
	if len(sk.Sk) != mode.SkBytes() {
		t.Errorf("expected sk len %d, got %d", mode.SkBytes(), len(sk.Sk))
	}

	msg := []byte("Hello, SLH-DSA!")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != mode.SigBytes() {
		t.Errorf("expected sig len %d, got %d", mode.SigBytes(), len(sig))
	}

	if !pk.Verify(msg, sig) {
		t.Error("signature verification failed")
	}

	if pk.Verify([]byte("wrong msg"), sig) {
		t.Error("signature verification succeeded for wrong message")
	}

	// modify sig
	wrongSig := make([]byte, len(sig))
	copy(wrongSig, sig)
	wrongSig[0] ^= 1
	if pk.Verify(msg, wrongSig) {
		t.Error("signature verification succeeded for modified signature")
	}
}

func TestAllModes(t *testing.T) {
	modes := []*SlhDsaMode{
		SlhDsaShake128s, SlhDsaShake128f,
		SlhDsaShake192s, SlhDsaShake192f,
		SlhDsaShake256s, SlhDsaShake256f,
		SlhDsaSha2_128s, SlhDsaSha2_128f,
		SlhDsaSha2_192s, SlhDsaSha2_192f,
		SlhDsaSha2_256s, SlhDsaSha2_256f,
	}

	for _, mode := range modes {
		t.Run(mode.Name, func(t *testing.T) {
			sk, pk, err := GenerateKey(mode)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			msg := []byte("test message")
			sig, err := sk.Sign(msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if !pk.Verify(msg, sig) {
				t.Errorf("verification failed for %s", mode.Name)
			}
		})
	}
}

func TestSignDeterministic(t *testing.T) {
	mode := SlhDsaShake128f
	sk, _, err := GenerateKey(mode)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	msg := []byte("deterministic test")
	sig1, _ := sk.Sign(msg)
	sig2, _ := sk.Sign(msg)

	if !bytes.Equal(sig1, sig2) {
		t.Error("signatures are not deterministic")
	}
}
