package slhdsa

import (
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

type SpxCtx struct {
	PubSeed []byte
	SkSeed  []byte
}

func NewSpxCtx(n int) *SpxCtx {
	return &SpxCtx{
		PubSeed: make([]byte, n),
		SkSeed:  make([]byte, n),
	}
}

func shake256(out []byte, inputs [][]byte) {
	hasher := sha3.NewShake256()
	for _, inp := range inputs {
		hasher.Write(inp)
	}
	hasher.Read(out)
}

func sha256hash(out []byte, inputs [][]byte) {
	hasher := sha256.New()
	for _, inp := range inputs {
		hasher.Write(inp)
	}
	result := hasher.Sum(nil)
	length := len(out)
	if length > 32 {
		length = 32
	}
	copy(out[:length], result[:length])
}

func sha256Full(inputs [][]byte) []byte {
	hasher := sha256.New()
	for _, inp := range inputs {
		hasher.Write(inp)
	}
	return hasher.Sum(nil)
}

func PrfAddr(out []byte, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	if mode.Hash == HashShake {
		shake256(out[:mode.N], [][]byte{ctx.PubSeed, addr[:], ctx.SkSeed})
	} else {
		padded := make([]byte, 0, 64+22+len(ctx.SkSeed))
		padded = append(padded, ctx.PubSeed...)
		if len(ctx.PubSeed) < 64 {
			padded = append(padded, make([]byte, 64-len(ctx.PubSeed))...)
		}
		padded = append(padded, addr[:22]...)
		padded = append(padded, ctx.SkSeed...)
		sha256hash(out[:mode.N], [][]byte{padded})
	}
}

func GenMessageRandom(rOut []byte, skPrf []byte, optrand []byte, m []byte, mode *SlhDsaMode) {
	if mode.Hash == HashShake {
		shake256(rOut[:mode.N], [][]byte{skPrf, optrand, m})
	} else {
		blockSize := 64
		ipad := make([]byte, blockSize)
		for i := 0; i < blockSize; i++ {
			ipad[i] = 0x36
		}
		for i := 0; i < mode.N && i < blockSize; i++ {
			ipad[i] ^= skPrf[i]
		}
		inner := sha256Full([][]byte{ipad, optrand, m})

		opad := make([]byte, blockSize)
		for i := 0; i < blockSize; i++ {
			opad[i] = 0x5c
		}
		for i := 0; i < mode.N && i < blockSize; i++ {
			opad[i] ^= skPrf[i]
		}
		result := sha256Full([][]byte{opad, inner})
		copy(rOut[:mode.N], result[:mode.N])
	}
}

func mgf1Sha256(seed []byte, outLen int) []byte {
	out := make([]byte, 0, outLen)
	var counter uint32 = 0
	for len(out) < outLen {
		ctr := uint32ToBytes(counter)
		block := sha256Full([][]byte{seed, ctr})
		remaining := outLen - len(out)
		if remaining > 32 {
			remaining = 32
		}
		out = append(out, block[:remaining]...)
		counter++
	}
	return out
}

func HashMessage(digest []byte, tree *uint64, leafIdx *uint32, r []byte, pk []byte, m []byte, mode *SlhDsaMode) {
	dgstBytes := mode.DgstBytes()
	var buf []byte

	if mode.Hash == HashShake {
		buf = make([]byte, dgstBytes)
		shake256(buf, [][]byte{r[:mode.N], pk[:mode.PkBytes()], m})
	} else {
		seedHash := sha256Full([][]byte{r[:mode.N], pk[:mode.PkBytes()], m})
		mgfSeed := make([]byte, 0, mode.N+mode.N+32)
		mgfSeed = append(mgfSeed, r[:mode.N]...)
		mgfSeed = append(mgfSeed, pk[:mode.N]...)
		mgfSeed = append(mgfSeed, seedHash...)
		buf = mgf1Sha256(mgfSeed, dgstBytes)
	}

	fmb := mode.ForsMsgBytes()
	copy(digest[:fmb], buf[:fmb])

	treeBits := mode.TreeBits()
	treeBytes := mode.TreeBytes()
	leafBytes := mode.LeafBytes()

	*tree = bytesToUint64(buf[fmb:], treeBytes)
	*tree &= (^uint64(0)) >> (64 - treeBits)

	*leafIdx = uint32(bytesToUint64(buf[fmb+treeBytes:], leafBytes))
	*leafIdx &= (^uint32(0)) >> (32 - mode.LeafBits())
}
