package slhdsa

func Thash(out []byte, input []byte, inblocks int, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	inputLen := inblocks * mode.N

	if mode.Hash == HashShake {
		shake256(out[:mode.N], [][]byte{ctx.PubSeed, addr[:], input[:inputLen]})
	} else {
		padded := make([]byte, 0, 64+22+inputLen)
		padded = append(padded, ctx.PubSeed...)
		if len(ctx.PubSeed) < 64 {
			padded = append(padded, make([]byte, 64-len(ctx.PubSeed))...)
		}
		padded = append(padded, addr[:22]...)
		padded = append(padded, input[:inputLen]...)
		sha256hash(out[:mode.N], [][]byte{padded})
	}
}
