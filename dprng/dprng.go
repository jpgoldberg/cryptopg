// Package dprng provides a deterministic (seedable) pseudo-random number generator
package dprng

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// DPRNG is our deterministic Pseudo-Random Byte Generator
type DPRNG struct {
	block     cipher.Block
	BlockSize int
	stream    cipher.Stream
}

// NewDPRNG sets up a new DPRNG with seed
func NewDPRNG(seed []byte) *DPRNG {
	d := new(DPRNG)
	var err error

	if !(len(seed) == 16 || len(seed) == 24 || len(seed) == 32) {
		fmt.Println("Seed:", seed)
		fmt.Println("len:", len(seed))
		panic("bad seed")
	}
	d.block, err = aes.NewCipher(seed)
	if err != nil {
		panic(err)
	}

	d.BlockSize = d.block.BlockSize()
	// use 0 as iv and plaintext(security is in the seed)
	iv := make([]byte, d.BlockSize)

	d.stream = cipher.NewOFB(d.block, iv[:])

	return d

}

// Read from the RNG.
func (d DPRNG) Read(result []byte) (n int, err error) {

	length := len(result)
	src := make([]byte, length)
	d.stream.XORKeyStream(result, src)
	return length, nil
}
