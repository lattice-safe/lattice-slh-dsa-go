package slhdsa

func baseW(output []uint32, outLen int, input []byte) {
	inIdx := 0
	var bits uint32 = 0
	var total uint32 = 0

	for i := 0; i < outLen; i++ {
		if bits == 0 {
			total = uint32(input[inIdx])
			inIdx++
			bits += 8
		}
		bits -= 4
		output[i] = (total >> bits) & 15
	}
}

func wotsChecksum(csumOutput []uint32, msgBaseW []uint32, mode *SlhDsaMode) {
	var csum uint32 = 0
	len1 := mode.WotsLen1()
	for i := 0; i < len1; i++ {
		csum += 15 - msgBaseW[i]
	}

	csumBits := mode.WotsLen2() * 4
	csum <<= (8 - (csumBits % 8)) % 8

	csumBytes := (csumBits + 7) / 8
	csumBuf := make([]byte, csumBytes)
	for i := range csumBuf {
		csumBuf[i] = byte(csum >> (8 * (csumBytes - 1 - i)))
	}

	baseW(csumOutput, mode.WotsLen2(), csumBuf)
}

func ChainLengths(lengths []uint32, msg []byte, mode *SlhDsaMode) {
	baseW(lengths, mode.WotsLen1(), msg)
	len1 := mode.WotsLen1()
	csumOut := make([]uint32, mode.WotsLen2())
	wotsChecksum(csumOut, lengths[:len1], mode)
	copy(lengths[len1:len1+mode.WotsLen2()], csumOut)
}

func genChain(out []byte, input []byte, start uint32, steps uint32, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	copy(out[:mode.N], input[:mode.N])

	tmp := make([]byte, mode.N)
	for i := start; i < start+steps; i++ {
		SetHashAddr(addr, i, mode)
		copy(tmp, out[:mode.N])
		Thash(out, tmp, 1, ctx, addr, mode)
	}
}

func WotsPkFromSig(pk []byte, sig []byte, msg []byte, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	wotsLen := mode.WotsLen()
	n := mode.N
	w := uint32(16)

	lengths := make([]uint32, wotsLen)
	ChainLengths(lengths, msg, mode)

	chainOut := make([]byte, n)
	for i := 0; i < wotsLen; i++ {
		SetChainAddr(addr, uint32(i), mode)
		genChain(chainOut, sig[i*n:(i+1)*n], lengths[i], w-1-lengths[i], ctx, addr, mode)
		copy(pk[i*n:(i+1)*n], chainOut)
	}
}

func WotsSign(sig []byte, msg []byte, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	wotsLen := mode.WotsLen()
	n := mode.N

	lengths := make([]uint32, wotsLen)
	ChainLengths(lengths, msg, mode)

	sk := make([]byte, n)
	chainOut := make([]byte, n)

	for i := 0; i < wotsLen; i++ {
		SetChainAddr(addr, uint32(i), mode)
		SetHashAddr(addr, 0, mode)

		SetType(addr, AddrTypeWotsprf, mode)
		for j := range sk {
			sk[j] = 0
		}
		PrfAddr(sk, ctx, addr, mode)

		SetType(addr, AddrTypeWots, mode)

		genChain(chainOut, sk, 0, lengths[i], ctx, addr, mode)
		copy(sig[i*n:(i+1)*n], chainOut)
	}

	for i := range sk {
		sk[i] = 0 // basic zeroize
	}
}
