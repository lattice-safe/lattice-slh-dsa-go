package slhdsa

func wotsGenLeafAndSign(
	leaf []byte,
	wotsSig []byte, // If nil, we are not signing
	root []byte,
	ctx *SpxCtx,
	leafIdx uint32,
	treeAddr *Addr,
	mode *SlhDsaMode,
) {
	n := mode.N
	wotsLen := mode.WotsLen()

	var leafAddr Addr
	var pkAddr Addr
	CopySubtreeAddr(&leafAddr, treeAddr, mode)
	CopySubtreeAddr(&pkAddr, treeAddr, mode)
	SetType(&leafAddr, AddrTypeWots, mode)
	SetType(&pkAddr, AddrTypeWotspk, mode)
	SetKeypairAddr(&leafAddr, leafIdx, mode)
	CopyKeypairAddr(&pkAddr, &leafAddr, mode)

	steps := make([]uint32, wotsLen)
	if wotsSig != nil {
		ChainLengths(steps, root, mode)
	}

	wotsPk := make([]byte, wotsLen*n)
	isSigning := wotsSig != nil

	sk := make([]byte, n)
	val := make([]byte, n)

	for i := 0; i < wotsLen; i++ {
		SetChainAddr(&leafAddr, uint32(i), mode)
		SetHashAddr(&leafAddr, 0, mode)

		SetType(&leafAddr, AddrTypeWotsprf, mode)
		for j := range sk {
			sk[j] = 0
		}
		PrfAddr(sk, ctx, &leafAddr, mode)
		SetType(&leafAddr, AddrTypeWots, mode)

		copy(val, sk)

		if isSigning {
			for j := uint32(0); j < steps[i]; j++ {
				SetHashAddr(&leafAddr, j, mode)
				tmp := make([]byte, n)
				copy(tmp, val)
				Thash(val, tmp, 1, ctx, &leafAddr, mode)
			}
			if wotsSig != nil {
				copy(wotsSig[i*n:(i+1)*n], val)
			}

			for j := steps[i]; j < uint32(mode.WotsW-1); j++ {
				SetHashAddr(&leafAddr, j, mode)
				tmp := make([]byte, n)
				copy(tmp, val)
				Thash(val, tmp, 1, ctx, &leafAddr, mode)
			}
		} else {
			for j := uint32(0); j < uint32(mode.WotsW-1); j++ {
				SetHashAddr(&leafAddr, j, mode)
				tmp := make([]byte, n)
				copy(tmp, val)
				Thash(val, tmp, 1, ctx, &leafAddr, mode)
			}
		}

		copy(wotsPk[i*n:(i+1)*n], val)
	}

	for i := range sk {
		sk[i] = 0 // basic zeroize
	}

	Thash(leaf, wotsPk, wotsLen, ctx, &pkAddr, mode)
}

func MerkleSign(
	sig []byte,
	root []byte,
	ctx *SpxCtx,
	wotsAddr *Addr,
	treeAddr *Addr,
	idxLeaf uint32,
	mode *SlhDsaMode,
) {
	n := mode.N
	treeHeight := mode.TreeHeight()
	numLeaves := 1 << treeHeight
	wotsBytes := mode.WotsBytes()

	leaves := make([]byte, numLeaves*n)

	for i := 0; i < numLeaves; i++ {
		if uint32(i) == idxLeaf {
			rootCopy := make([]byte, len(root))
			copy(rootCopy, root)
			wotsGenLeafAndSign(
				leaves[i*n:(i+1)*n],
				sig[:wotsBytes],
				rootCopy,
				ctx,
				uint32(i),
				treeAddr,
				mode,
			)
		} else {
			wotsGenLeafAndSign(
				leaves[i*n:(i+1)*n],
				nil,
				nil,
				ctx,
				uint32(i),
				treeAddr,
				mode,
			)
		}
	}

	var tAddr Addr
	CopySubtreeAddr(&tAddr, treeAddr, mode)
	SetType(&tAddr, AddrTypeHashtree, mode)

	Treehash(
		root,
		sig[wotsBytes:],
		leaves,
		idxLeaf,
		0,
		treeHeight,
		ctx,
		&tAddr,
		mode,
	)
}

func MerkleGenRoot(root []byte, ctx *SpxCtx, mode *SlhDsaMode) {
	n := mode.N
	treeHeight := mode.TreeHeight()
	numLeaves := 1 << treeHeight

	var topTreeAddr Addr
	SetLayerAddr(&topTreeAddr, uint32(mode.D-1), mode)

	leaves := make([]byte, numLeaves*n)
	for i := 0; i < numLeaves; i++ {
		wotsGenLeafAndSign(
			leaves[i*n:(i+1)*n],
			nil,
			nil,
			ctx,
			uint32(i),
			&topTreeAddr,
			mode,
		)
	}

	var tAddr Addr
	CopySubtreeAddr(&tAddr, &topTreeAddr, mode)
	SetType(&tAddr, AddrTypeHashtree, mode)

	dummyAuth := make([]byte, treeHeight*n)
	Treehash(
		root,
		dummyAuth,
		leaves,
		0,
		0,
		treeHeight,
		ctx,
		&tAddr,
		mode,
	)
}
