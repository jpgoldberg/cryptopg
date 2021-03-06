// Package dprng provides a deterministic (seedable) pseudo-random number generato.
// I do not know why I picked OFB mode for the steam cipher.
// CTR would probably have been faster.
package dprng

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// DPRNG is our deterministic Pseudo-Random Byte Generator
// Public interface is through functions only
type DPRNG struct {
	block     cipher.Block
	blockSize int
	stream    cipher.Stream
}

// NewDPRNG sets up a new DPRNG with seed, which must be a valid AES key size
// This uses AES in OFB mode to create a stream that just encrypts zeros
func NewDPRNG(seed []byte) (d *DPRNG, err error) {
	d = new(DPRNG)

	if !(len(seed) == 16 || len(seed) == 24 || len(seed) == 32) {
		return nil, fmt.Errorf("bad seed length: %d", len(seed))
	}

	d.block, err = aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	d.blockSize = d.block.BlockSize()

	// use 0 as iv and plaintext(security is in the seed)
	iv := make([]byte, d.blockSize)
	d.stream = cipher.NewOFB(d.block, iv[:])

	return d, nil

}

// Read from the RNG into the result. Returns the size in bytes of the result
func (d DPRNG) Read(result []byte) (n int, err error) {

	n = len(result)
	src := make([]byte, n)
	d.stream.XORKeyStream(result, src)
	return n, nil
}
