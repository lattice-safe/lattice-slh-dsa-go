package slhdsa_test

import (
	"fmt"
	"log"

	"github.com/lattice-safe/lattice-slh-dsa-go"
)

func ExampleGenerateKey() {
	// Generate a keypair using the SHAKE-128 fast parameter set
	sk, pk, err := slhdsa.GenerateKey(slhdsa.SlhDsaShake128f)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	// The message to sign
	msg := []byte("Post-quantum cryptography in Go!")

	// Sign the message
	sig, err := sk.Sign(msg)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	isValid := pk.Verify(msg, sig)
	fmt.Printf("Signature is valid: %t\n", isValid)

	// Output:
	// Signature is valid: true
}
