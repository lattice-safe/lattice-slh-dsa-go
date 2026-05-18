package slhdsa

import "encoding/binary"

// bytesToUint64 converts a big-endian byte slice to uint64.
// It pads with leading zeros if the slice is smaller than 8 bytes.
func bytesToUint64(b []byte, size int) uint64 {
	var val uint64
	for i := 0; i < size; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val
}

// uint64ToBytes converts a uint64 to a big-endian byte slice of specified size.
func uint64ToBytes(val uint64, size int) []byte {
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(val)
		val >>= 8
	}
	return out
}

// uint32ToBytes converts a uint32 to a 4-byte big-endian slice.
func uint32ToBytes(val uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, val)
	return out
}

// bytesToUint32 converts a 4-byte big-endian slice to uint32.
func bytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
