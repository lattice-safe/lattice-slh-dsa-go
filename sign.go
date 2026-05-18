package slhdsa

import "crypto/subtle"

func KeygenSeed(mode *SlhDsaMode, seed []byte) ([]byte, []byte) {
	n := mode.N
	if len(seed) < mode.SeedBytes() {
		return nil, nil
	}

	sk := make([]byte, mode.SkBytes())
	pk := make([]byte, mode.PkBytes())

	copy(sk[:3*n], seed[:3*n])
	copy(pk[:n], seed[2*n:3*n])

	ctx := NewSpxCtx(n)
	copy(ctx.PubSeed, pk[:n])
	copy(ctx.SkSeed, seed[:n])

	root := make([]byte, n)
	MerkleGenRoot(root, ctx, mode)

	copy(sk[3*n:4*n], root)
	copy(pk[n:2*n], root)

	return pk, sk
}

func Sign(sk []byte, m []byte, mode *SlhDsaMode) []byte {
	n := mode.N

	if len(sk) < mode.SkBytes() {
		return nil
	}

	skSeed := sk[:n]
	skPrf := sk[n : 2*n]
	pk := sk[2*n:]

	ctx := NewSpxCtx(n)
	copy(ctx.SkSeed, skSeed)
	copy(ctx.PubSeed, pk[:n])

	sig := make([]byte, mode.SigBytes())
	sigOffset := 0

	optrand := make([]byte, n)
	GenMessageRandom(sig[:n], skPrf, optrand, m, mode)
	r := make([]byte, n)
	copy(r, sig[:n])
	sigOffset += n

	mhash := make([]byte, mode.ForsMsgBytes())
	var tree uint64 = 0
	var idxLeaf uint32 = 0
	HashMessage(mhash, &tree, &idxLeaf, r, pk, m, mode)

	var wotsAddr Addr
	var treeAddr Addr
	SetType(&wotsAddr, AddrTypeWots, mode)
	SetType(&treeAddr, AddrTypeHashtree, mode)
	SetTreeAddr(&wotsAddr, tree, mode)
	SetKeypairAddr(&wotsAddr, idxLeaf, mode)

	forsRoot := make([]byte, n)
	ForsSign(
		sig[sigOffset:],
		forsRoot,
		mhash,
		ctx,
		&wotsAddr,
		mode,
	)
	sigOffset += mode.ForsBytes()

	root := make([]byte, n)
	copy(root, forsRoot)

	for i := 0; i < mode.D; i++ {
		SetLayerAddr(&treeAddr, uint32(i), mode)
		SetTreeAddr(&treeAddr, tree, mode)

		CopySubtreeAddr(&wotsAddr, &treeAddr, mode)
		SetKeypairAddr(&wotsAddr, idxLeaf, mode)

		sigLen := mode.WotsBytes() + mode.TreeHeight()*n
		MerkleSign(
			sig[sigOffset:sigOffset+sigLen],
			root,
			ctx,
			&wotsAddr,
			&treeAddr,
			idxLeaf,
			mode,
		)
		sigOffset += sigLen

		idxLeaf = uint32(tree & ((1 << mode.TreeHeight()) - 1))
		tree >>= mode.TreeHeight()
	}

	return sig
}

func Verify(pk []byte, sig []byte, m []byte, mode *SlhDsaMode) bool {
	n := mode.N

	if len(sig) != mode.SigBytes() {
		return false
	}

	if len(pk) != mode.PkBytes() {
		return false
	}

	pubSeed := pk[:n]
	pubRoot := pk[n : 2*n]

	ctx := NewSpxCtx(n)
	copy(ctx.PubSeed, pubSeed)

	sigOffset := 0

	r := sig[:n]
	sigOffset += n

	mhash := make([]byte, mode.ForsMsgBytes())
	var tree uint64 = 0
	var idxLeaf uint32 = 0
	HashMessage(mhash, &tree, &idxLeaf, r, pk, m, mode)

	var wotsAddr Addr
	var treeAddr Addr
	var wotsPkAddr Addr

	SetType(&wotsAddr, AddrTypeWots, mode)
	SetType(&treeAddr, AddrTypeHashtree, mode)
	SetType(&wotsPkAddr, AddrTypeWotspk, mode)

	SetTreeAddr(&wotsAddr, tree, mode)
	SetKeypairAddr(&wotsAddr, idxLeaf, mode)

	root := make([]byte, n)
	ForsPkFromSig(
		root,
		sig[sigOffset:],
		mhash,
		ctx,
		&wotsAddr,
		mode,
	)
	sigOffset += mode.ForsBytes()

	for i := 0; i < mode.D; i++ {
		SetLayerAddr(&treeAddr, uint32(i), mode)
		SetTreeAddr(&treeAddr, tree, mode)

		CopySubtreeAddr(&wotsAddr, &treeAddr, mode)
		SetKeypairAddr(&wotsAddr, idxLeaf, mode)
		CopyKeypairAddr(&wotsPkAddr, &wotsAddr, mode)

		wotsPk := make([]byte, mode.WotsBytes())
		WotsPkFromSig(
			wotsPk,
			sig[sigOffset:],
			root,
			ctx,
			&wotsAddr,
			mode,
		)
		sigOffset += mode.WotsBytes()

		leaf := make([]byte, n)
		Thash(
			leaf,
			wotsPk,
			mode.WotsLen(),
			ctx,
			&wotsPkAddr,
			mode,
		)

		ComputeRoot(
			root,
			leaf,
			idxLeaf,
			0,
			sig[sigOffset:],
			mode.TreeHeight(),
			ctx,
			&treeAddr,
			mode,
		)
		sigOffset += mode.TreeHeight() * n

		idxLeaf = uint32(tree & ((1 << mode.TreeHeight()) - 1))
		tree >>= mode.TreeHeight()
	}

	return subtle.ConstantTimeCompare(root, pubRoot) == 1
}
