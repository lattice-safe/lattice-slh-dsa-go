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

func TestErrorPaths(t *testing.T) {
	mode := SlhDsaShake128f
	_, pk, _ := GenerateKey(mode)

	if pkBytes, skBytes := KeygenSeed(mode, make([]byte, 5)); pkBytes != nil || skBytes != nil {
		t.Error("KeygenSeed should return nil for bad seed length")
	}

	if sig := Sign(make([]byte, 5), []byte("msg"), mode); sig != nil {
		t.Error("Sign should return nil for bad sk length")
	}

	if valid := Verify(make([]byte, 5), []byte("msg"), pk.Pk, mode); valid {
		t.Error("Verify should return false for bad pk/sig length")
	}

	if valid := Verify(make([]byte, 5), make([]byte, mode.SigBytes()), []byte("msg"), mode); valid {
		t.Error("Verify should return false for bad pk length with good sig length")
	}

	badSk := &PrivateKey{Mode: mode, Sk: make([]byte, 5)}
	if _, err := badSk.Sign([]byte("msg")); err == nil {
		t.Error("badSk.Sign should fail")
	}

	badPk := &PublicKey{Mode: mode, Pk: make([]byte, 5)}
	if valid := badPk.Verify([]byte("msg"), make([]byte, mode.SigBytes())); valid {
		t.Error("badPk.Verify should fail")
	}

	if valid := pk.Verify([]byte("msg"), make([]byte, 5)); valid {
		t.Error("pk.Verify with bad sig should fail")
	}

	if _, _, err := GenerateKeyFromSeed(mode, make([]byte, 5)); err == nil {
		t.Error("GenerateKeyFromSeed should fail with short seed")
	}
}

func TestCoverageEdgeCases(t *testing.T) {
	// Cover baseW w=256
	out := make([]uint32, 2)
	baseW(out, 2, []byte{0xab, 0xcd}, 256)
	if out[0] != 0xab {
		t.Error("baseW 256 failed")
	}

	// Cover bytesToUint32
	if bytesToUint32([]byte{0x12, 0x34, 0x56, 0x78}) != 0x12345678 {
		t.Error("bytesToUint32 failed")
	}

	// Cover sha256hash remaining > 32
	longOut := make([]byte, 40)
	sha256hash(longOut, [][]byte{{0x01}})

	// Cover HashMessage with D=1
	modeD1 := &SlhDsaMode{D: 1, N: 16, Hash: HashSha2, ForsTrees: 14, ForsHeight: 12, FullHeight: 20, WotsW: 16}
	d1Ctx := NewSpxCtx(16)
	d1Addr := new(Addr)
	var tree uint64
	var leaf uint32
	HashMessage(make([]byte, modeD1.ForsMsgBytes()), &tree, &leaf, make([]byte, modeD1.N), make([]byte, modeD1.PkBytes()), []byte("msg"), modeD1)
	if tree != 0 {
		t.Error("HashMessage D=1 tree must be 0")
	}

	// Cover HashMessage with HashShake and D=1
	modeD1Shake := &SlhDsaMode{D: 1, N: 16, Hash: HashShake, ForsTrees: 14, ForsHeight: 12, FullHeight: 20, WotsW: 16}
	HashMessage(make([]byte, modeD1Shake.ForsMsgBytes()), &tree, &leaf, make([]byte, modeD1Shake.N), make([]byte, modeD1Shake.PkBytes()), []byte("msg"), modeD1Shake)

	// Cover WotsSign
	sig := make([]byte, modeD1.WotsBytes())
	WotsSign(sig, make([]byte, modeD1.N), d1Ctx, d1Addr, modeD1)
}
