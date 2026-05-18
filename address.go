package slhdsa

const (
	AddrTypeWots     uint8 = 0
	AddrTypeWotspk   uint8 = 1
	AddrTypeHashtree uint8 = 2
	AddrTypeForstree uint8 = 3
	AddrTypeForspk   uint8 = 4
	AddrTypeWotsprf  uint8 = 5
	AddrTypeForsprf  uint8 = 6
)

const AddrBytes = 32

type Addr [AddrBytes]byte

func offsets(mode *SlhDsaMode) (layer, tree, typ, kp, chain, hash, treeHgt, treeIdx int) {
	if mode.Hash == HashShake {
		return 3, 8, 19, 20, 27, 31, 27, 28
	}
	return 0, 1, 9, 10, 17, 21, 17, 18
}

func SetLayerAddr(addr *Addr, layer uint32, mode *SlhDsaMode) {
	offLayer, _, _, _, _, _, _, _ := offsets(mode)
	addr[offLayer] = byte(layer)
}

func SetTreeAddr(addr *Addr, tree uint64, mode *SlhDsaMode) {
	_, offTree, _, _, _, _, _, _ := offsets(mode)
	bytes := uint64ToBytes(tree, 8)
	copy(addr[offTree:offTree+8], bytes)
}

func SetType(addr *Addr, typ uint8, mode *SlhDsaMode) {
	_, _, offType, _, _, _, _, _ := offsets(mode)
	addr[offType] = typ
}

func CopySubtreeAddr(out *Addr, src *Addr, mode *SlhDsaMode) {
	_, offTree, _, _, _, _, _, _ := offsets(mode)
	end := offTree + 8
	copy(out[:end], src[:end])
}

func SetKeypairAddr(addr *Addr, keypair uint32, mode *SlhDsaMode) {
	_, _, _, offKp, _, _, _, _ := offsets(mode)
	bytes := uint32ToBytes(keypair)
	copy(addr[offKp:offKp+4], bytes)
}

func CopyKeypairAddr(out *Addr, src *Addr, mode *SlhDsaMode) {
	_, offTree, _, offKp, _, _, _, _ := offsets(mode)
	end := offTree + 8
	copy(out[:end], src[:end])
	copy(out[offKp:offKp+4], src[offKp:offKp+4])
}

func SetChainAddr(addr *Addr, chain uint32, mode *SlhDsaMode) {
	_, _, _, _, offChain, _, _, _ := offsets(mode)
	addr[offChain] = byte(chain)
}

func SetHashAddr(addr *Addr, hash uint32, mode *SlhDsaMode) {
	_, _, _, _, _, offHash, _, _ := offsets(mode)
	addr[offHash] = byte(hash)
}

func SetTreeHeight(addr *Addr, height uint32, mode *SlhDsaMode) {
	_, _, _, _, _, _, offHgt, _ := offsets(mode)
	addr[offHgt] = byte(height)
}

func SetTreeIndex(addr *Addr, index uint32, mode *SlhDsaMode) {
	_, _, _, _, _, _, _, offIdx := offsets(mode)
	bytes := uint32ToBytes(index)
	copy(addr[offIdx:offIdx+4], bytes)
}
