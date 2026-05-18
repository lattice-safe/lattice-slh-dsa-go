package slhdsa

type HashFamily int

const (
	HashShake HashFamily = iota
	HashSha2
)

// SlhDsaMode holds the parameter set for SLH-DSA.
type SlhDsaMode struct {
	Name       string
	Hash       HashFamily
	N          int
	FullHeight int
	D          int
	ForsHeight int
	ForsTrees  int
}

func (m *SlhDsaMode) WotsLen1() int {
	return 2 * m.N
}

func (m *SlhDsaMode) WotsLen2() int {
	return 3
}

func (m *SlhDsaMode) WotsLen() int {
	return 2*m.N + 3
}

func (m *SlhDsaMode) WotsBytes() int {
	return m.WotsLen() * m.N
}

func (m *SlhDsaMode) TreeHeight() int {
	return m.FullHeight / m.D
}

func (m *SlhDsaMode) ForsMsgBytes() int {
	return (m.ForsHeight*m.ForsTrees + 7) / 8
}

func (m *SlhDsaMode) ForsBytes() int {
	return (m.ForsHeight + 1) * m.ForsTrees * m.N
}

// SigBytes returns the total signature size in bytes.
func (m *SlhDsaMode) SigBytes() int {
	return m.N + m.ForsBytes() + m.D*m.WotsBytes() + m.FullHeight*m.N
}

// PkBytes returns the public key size in bytes.
func (m *SlhDsaMode) PkBytes() int {
	return 2 * m.N
}

// SkBytes returns the secret key size in bytes.
func (m *SlhDsaMode) SkBytes() int {
	return 2*m.N + m.PkBytes()
}

// SeedBytes returns the seed size (3 * n).
func (m *SlhDsaMode) SeedBytes() int {
	return 3 * m.N
}

func (m *SlhDsaMode) TreeBits() int {
	return m.TreeHeight() * (m.D - 1)
}

func (m *SlhDsaMode) TreeBytes() int {
	return (m.TreeBits() + 7) / 8
}

func (m *SlhDsaMode) LeafBits() int {
	return m.TreeHeight()
}

func (m *SlhDsaMode) LeafBytes() int {
	return (m.LeafBits() + 7) / 8
}

func (m *SlhDsaMode) DgstBytes() int {
	return m.ForsMsgBytes() + m.TreeBytes() + m.LeafBytes()
}

// FIPS 205 parameter sets — SHAKE variants
var SlhDsaShake128s = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-128s",
	Hash:       HashShake,
	N:          16,
	FullHeight: 63,
	D:          7,
	ForsHeight: 12,
	ForsTrees:  14,
}
var SlhDsaShake128f = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-128f",
	Hash:       HashShake,
	N:          16,
	FullHeight: 66,
	D:          22,
	ForsHeight: 6,
	ForsTrees:  33,
}
var SlhDsaShake192s = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-192s",
	Hash:       HashShake,
	N:          24,
	FullHeight: 63,
	D:          7,
	ForsHeight: 14,
	ForsTrees:  17,
}
var SlhDsaShake192f = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-192f",
	Hash:       HashShake,
	N:          24,
	FullHeight: 66,
	D:          22,
	ForsHeight: 8,
	ForsTrees:  33,
}
var SlhDsaShake256s = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-256s",
	Hash:       HashShake,
	N:          32,
	FullHeight: 64,
	D:          8,
	ForsHeight: 14,
	ForsTrees:  22,
}
var SlhDsaShake256f = &SlhDsaMode{
	Name:       "SLH-DSA-SHAKE-256f",
	Hash:       HashShake,
	N:          32,
	FullHeight: 68,
	D:          17,
	ForsHeight: 9,
	ForsTrees:  35,
}

// FIPS 205 parameter sets — SHA-2 variants
var SlhDsaSha2_128s = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-128s",
	Hash:       HashSha2,
	N:          16,
	FullHeight: 63,
	D:          7,
	ForsHeight: 12,
	ForsTrees:  14,
}
var SlhDsaSha2_128f = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-128f",
	Hash:       HashSha2,
	N:          16,
	FullHeight: 66,
	D:          22,
	ForsHeight: 6,
	ForsTrees:  33,
}
var SlhDsaSha2_192s = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-192s",
	Hash:       HashSha2,
	N:          24,
	FullHeight: 63,
	D:          7,
	ForsHeight: 14,
	ForsTrees:  17,
}
var SlhDsaSha2_192f = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-192f",
	Hash:       HashSha2,
	N:          24,
	FullHeight: 66,
	D:          22,
	ForsHeight: 8,
	ForsTrees:  33,
}
var SlhDsaSha2_256s = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-256s",
	Hash:       HashSha2,
	N:          32,
	FullHeight: 64,
	D:          8,
	ForsHeight: 14,
	ForsTrees:  22,
}
var SlhDsaSha2_256f = &SlhDsaMode{
	Name:       "SLH-DSA-SHA2-256f",
	Hash:       HashSha2,
	N:          32,
	FullHeight: 68,
	D:          17,
	ForsHeight: 9,
	ForsTrees:  35,
}
