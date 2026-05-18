package slhdsa

func messageToIndices(indices []uint32, m []byte, mode *SlhDsaMode) {
	offset := 0
	for i := 0; i < mode.ForsTrees; i++ {
		indices[i] = 0
		for j := 0; j < mode.ForsHeight; j++ {
			bit := (uint32(m[offset>>3]) >> (offset & 0x7)) & 1
			indices[i] ^= bit << j
			offset++
		}
	}
}

func forsGenSk(sk []byte, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	PrfAddr(sk, ctx, addr, mode)
}

func forsSkToLeaf(leaf []byte, sk []byte, ctx *SpxCtx, addr *Addr, mode *SlhDsaMode) {
	Thash(leaf, sk, 1, ctx, addr, mode)
}

func ComputeRoot(
	root []byte,
	leaf []byte,
	leafIdx uint32,
	idxOffset uint32,
	authPath []byte,
	treeHeight int,
	ctx *SpxCtx,
	addr *Addr,
	mode *SlhDsaMode,
) {
	n := mode.N
	buffer := make([]byte, 2*n)
	authOff := 0

	if (leafIdx & 1) != 0 {
		copy(buffer[n:2*n], leaf[:n])
		copy(buffer[:n], authPath[:n])
	} else {
		copy(buffer[:n], leaf[:n])
		copy(buffer[n:2*n], authPath[:n])
	}
	authOff += n

	for i := 0; i < treeHeight-1; i++ {
		leafIdx >>= 1
		idxOffset >>= 1
		SetTreeHeight(addr, uint32(i+1), mode)
		SetTreeIndex(addr, leafIdx+idxOffset, mode)

		bufCopy := make([]byte, len(buffer))
		copy(bufCopy, buffer)

		if (leafIdx & 1) != 0 {
			Thash(buffer[n:2*n], bufCopy, 2, ctx, addr, mode)
			copy(buffer[:n], authPath[authOff:authOff+n])
		} else {
			Thash(buffer[:n], bufCopy, 2, ctx, addr, mode)
			copy(buffer[n:2*n], authPath[authOff:authOff+n])
		}
		authOff += n
	}

	leafIdx >>= 1
	idxOffset >>= 1
	SetTreeHeight(addr, uint32(treeHeight), mode)
	SetTreeIndex(addr, leafIdx+idxOffset, mode)
	Thash(root, buffer, 2, ctx, addr, mode)
}

func Treehash(
	root []byte,
	authPath []byte,
	leaves []byte,
	leafIdx uint32,
	idxOffset uint32,
	treeHeight int,
	ctx *SpxCtx,
	addr *Addr,
	mode *SlhDsaMode,
) {
	n := mode.N
	numLeaves := uint32(1 << treeHeight)

	stack := make([]byte, (treeHeight+1)*n)
	heights := make([]uint32, treeHeight+1)
	offset := 0

	for idx := uint32(0); idx < numLeaves; idx++ {
		copy(stack[offset*n:(offset+1)*n], leaves[idx*uint32(n):(idx+1)*uint32(n)])
		offset++
		heights[offset-1] = 0

		if (leafIdx ^ 0x1) == idx {
			copy(authPath[:n], stack[(offset-1)*n:offset*n])
		}

		for offset >= 2 && heights[offset-1] == heights[offset-2] {
			treeIdx := idx >> (heights[offset-1] + 1)

			SetTreeHeight(addr, heights[offset-1]+1, mode)
			SetTreeIndex(addr, treeIdx+(idxOffset>>(heights[offset-1]+1)), mode)

			twoNodes := make([]byte, 2*n)
			copy(twoNodes, stack[(offset-2)*n:offset*n])

			Thash(stack[(offset-2)*n:(offset-1)*n], twoNodes, 2, ctx, addr, mode)
			offset--
			heights[offset-1]++

			if ((leafIdx >> heights[offset-1]) ^ 0x1) == treeIdx {
				h := int(heights[offset-1])
				copy(authPath[h*n:(h+1)*n], stack[(offset-1)*n:offset*n])
			}
		}
	}

	copy(root[:n], stack[:n])
}

func ForsSign(sig []byte, pk []byte, m []byte, ctx *SpxCtx, forsAddr *Addr, mode *SlhDsaMode) {
	n := mode.N
	indices := make([]uint32, mode.ForsTrees)
	messageToIndices(indices, m, mode)

	roots := make([]byte, mode.ForsTrees*n)
	sigOffset := 0

	for i := 0; i < mode.ForsTrees; i++ {
		idxOffset := uint32(i) * (1 << mode.ForsHeight)

		var forsLeafAddr Addr
		CopyKeypairAddr(&forsLeafAddr, forsAddr, mode)
		SetTreeIndex(&forsLeafAddr, indices[i]+idxOffset, mode)
		SetType(&forsLeafAddr, AddrTypeForsprf, mode)
		forsGenSk(sig[sigOffset:], ctx, &forsLeafAddr, mode)
		sigOffset += n

		treeSize := 1 << mode.ForsHeight
		leaves := make([]byte, treeSize*n)
		for j := 0; j < treeSize; j++ {
			var leafAddr Addr
			CopyKeypairAddr(&leafAddr, forsAddr, mode)
			SetTreeIndex(&leafAddr, uint32(j)+idxOffset, mode)
			SetType(&leafAddr, AddrTypeForsprf, mode)
			sk := make([]byte, n)
			forsGenSk(sk, ctx, &leafAddr, mode)

			SetType(&leafAddr, AddrTypeForstree, mode)
			forsSkToLeaf(leaves[j*n:(j+1)*n], sk, ctx, &leafAddr, mode)

			for k := range sk {
				sk[k] = 0 // basic zeroize
			}
		}

		var treeAddr Addr
		CopyKeypairAddr(&treeAddr, forsAddr, mode)
		SetType(&treeAddr, AddrTypeForstree, mode)

		Treehash(
			roots[i*n:(i+1)*n],
			sig[sigOffset:sigOffset+mode.ForsHeight*n],
			leaves,
			indices[i],
			idxOffset,
			mode.ForsHeight,
			ctx,
			&treeAddr,
			mode,
		)
		sigOffset += mode.ForsHeight * n
	}

	var forsPkAddr Addr
	CopyKeypairAddr(&forsPkAddr, forsAddr, mode)
	SetType(&forsPkAddr, AddrTypeForspk, mode)
	Thash(pk, roots, mode.ForsTrees, ctx, &forsPkAddr, mode)
}

func ForsPkFromSig(pk []byte, sig []byte, m []byte, ctx *SpxCtx, forsAddr *Addr, mode *SlhDsaMode) {
	n := mode.N
	indices := make([]uint32, mode.ForsTrees)
	messageToIndices(indices, m, mode)

	roots := make([]byte, mode.ForsTrees*n)
	sigOffset := 0

	for i := 0; i < mode.ForsTrees; i++ {
		idxOffset := uint32(i) * (1 << mode.ForsHeight)

		var forsTreeAddr Addr
		CopyKeypairAddr(&forsTreeAddr, forsAddr, mode)
		SetType(&forsTreeAddr, AddrTypeForstree, mode)
		SetTreeHeight(&forsTreeAddr, 0, mode)
		SetTreeIndex(&forsTreeAddr, indices[i]+idxOffset, mode)

		leaf := make([]byte, n)
		forsSkToLeaf(leaf, sig[sigOffset:sigOffset+n], ctx, &forsTreeAddr, mode)
		sigOffset += n

		ComputeRoot(
			roots[i*n:(i+1)*n],
			leaf,
			indices[i],
			idxOffset,
			sig[sigOffset:],
			mode.ForsHeight,
			ctx,
			&forsTreeAddr,
			mode,
		)
		sigOffset += mode.ForsHeight * n
	}

	var forsPkAddr Addr
	CopyKeypairAddr(&forsPkAddr, forsAddr, mode)
	SetType(&forsPkAddr, AddrTypeForspk, mode)
	Thash(pk, roots, mode.ForsTrees, ctx, &forsPkAddr, mode)
}
