package slhdsa

import (
	"crypto/rand"
	"errors"
)

var (
	ErrInvalidSeedLength = errors.New("invalid seed length")
	ErrInvalidKeyLength  = errors.New("invalid key length")
	ErrInvalidSignature  = errors.New("invalid signature")
)

// PublicKey represents an SLH-DSA public key.
type PublicKey struct {
	Mode *SlhDsaMode
	Pk   []byte
}

// PrivateKey represents an SLH-DSA private key.
type PrivateKey struct {
	Mode *SlhDsaMode
	Pk   []byte
	Sk   []byte
}

// GenerateKey generates a new SLH-DSA keypair using the specified parameter set.
// It reads cryptographic randomness from crypto/rand.
func GenerateKey(mode *SlhDsaMode) (*PrivateKey, *PublicKey, error) {
	seed := make([]byte, mode.SeedBytes())
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	pkBytes, skBytes := KeygenSeed(mode, seed)

	pk := &PublicKey{
		Mode: mode,
		Pk:   pkBytes,
	}

	sk := &PrivateKey{
		Mode: mode,
		Pk:   pkBytes,
		Sk:   skBytes,
	}

	return sk, pk, nil
}

// GenerateKeyFromSeed generates an SLH-DSA keypair deterministically from a given seed.
// The seed must be exactly mode.SeedBytes() in length.
func GenerateKeyFromSeed(mode *SlhDsaMode, seed []byte) (*PrivateKey, *PublicKey, error) {
	if len(seed) != mode.SeedBytes() {
		return nil, nil, ErrInvalidSeedLength
	}

	pkBytes, skBytes := KeygenSeed(mode, seed)

	pk := &PublicKey{
		Mode: mode,
		Pk:   pkBytes,
	}

	sk := &PrivateKey{
		Mode: mode,
		Pk:   pkBytes,
		Sk:   skBytes,
	}

	return sk, pk, nil
}

// Sign generates a deterministic SLH-DSA signature for the given message.
func (sk *PrivateKey) Sign(msg []byte) ([]byte, error) {
	if len(sk.Sk) != sk.Mode.SkBytes() {
		return nil, ErrInvalidKeyLength
	}

	return Sign(sk.Sk, msg, sk.Mode), nil
}

// Verify checks if the provided signature is valid for the given message.
func (pk *PublicKey) Verify(msg []byte, sig []byte) bool {
	if len(pk.Pk) != pk.Mode.PkBytes() {
		return false
	}
	return Verify(pk.Pk, sig, msg, pk.Mode)
}
