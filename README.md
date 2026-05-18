# lattice-slh-dsa-go

Pure Go implementation of **SLH-DSA** (FIPS 205) — the stateless hash-based digital signature scheme, also known as SPHINCS+.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Features

- ✅ **FIPS 205 compliant** — all 12 parameter sets (6 SHAKE + 6 SHA-2)
- 🐹 **Pure Go** — no CGO or assembly dependencies required
- 🧹 **Zeroization** — sensitive keys partially zeroized during signature execution
- 📦 **Typed safe API** — `PrivateKey`, `PublicKey`

## Parameter Sets

| Parameter Set | NIST Level | Sig Size | PK Size | SK Size |
|---|---|---|---|---|
| SLH-DSA-SHAKE-128s | 1 | ~7,856 B | 32 B | 64 B |
| SLH-DSA-SHAKE-128f | 1 | ~17,088 B | 32 B | 64 B |
| SLH-DSA-SHAKE-192s | 3 | ~16,224 B | 48 B | 96 B |
| SLH-DSA-SHAKE-192f | 3 | ~35,664 B | 48 B | 96 B |
| SLH-DSA-SHAKE-256s | 5 | ~29,792 B | 64 B | 128 B |
| SLH-DSA-SHAKE-256f | 5 | ~49,856 B | 64 B | 128 B |

## Quick Start

### Safe API (recommended)

```go
package main

import (
	"fmt"
	"log"

	"github.com/lattice-safe/lattice-slh-dsa-go"
)

func main() {
	// Generate a new keypair
	sk, pk, err := slhdsa.GenerateKey(slhdsa.SlhDsaShake128f)
	if err != nil {
		log.Fatal(err)
	}

	// Sign a message
	msg := []byte("Hello, post-quantum!")
	sig, err := sk.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}

	// Verify the signature
	valid := pk.Verify(msg, sig)
	fmt.Printf("Signature valid: %v\n", valid)
}
```

## Architecture

| Component | Description |
|---|---|
| `slhdsa.go` | **High-level typed API** — `PrivateKey`, `PublicKey` |
| `sign.go` | Top-level keygen, sign, verify logic |
| `params.go` | All 12 FIPS 205 parameter sets |
| `address.go` | ADRS structure with byte-level encoding (SHAKE/SHA-2 layouts) |
| `hash.go` | PRF, H_msg, gen_message_random (SHAKE-256 + SHA-256/HMAC) |
| `thash.go` | Tweakable hash T_l |
| `wots.go` | WOTS+ one-time signatures (base-w, chain, sign/verify) |
| `fors.go` | FORS few-time signatures (treehash + auth paths) |
| `merkle.go` | Hypertree Merkle signing and root generation |

## Part of lattice-safe-suite

This package implements **FIPS 205 (SLH-DSA)** as part of the `lattice-safe` ecosystem for Go:

| Standard | Crate/Package | Algorithm |
|---|---|---|
| FIPS 203 | `lattice-kyber-go` | ML-KEM (Kyber) |
| FIPS 204 | `dilithium-go` | ML-DSA (Dilithium) |
| FIPS 205 | **`lattice-slh-dsa-go`** | SLH-DSA (SPHINCS+) |
| FIPS 206 | `falcon-go` | FN-DSA (Falcon) |

## License

MIT
