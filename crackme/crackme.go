// Package crackme is for creating cracking challenges
// It is a useful (to me at least) tool for generating PBKDF2 password cracking
// challenges.
package crackme

import (
	rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"

	"golang.org/x/crypto/pbkdf2"
	// "github.com/jpgoldberg/cryptopg/crackme"
)

// Challenge has details for each PBKDF2 challenge
type Challenge struct {
	ID       string `json:"id"`
	Hint     string `json:"hint,omitempty"`
	IsSample bool   `json:"sample,omitempty"`
	PRF      string `json:"prf"`
	Rounds   int    `json:"rounds"`
	SaltHex  string `json:"salt"`
	DkHex    string `json:"derived,omitempty"`
	Pwd      string `json:"pwd,omitempty"`

	KeyLen  int    `json:"-"`
	Salt    []byte `json:"-"`
	Dk      []byte `json:"-"`
	prfHash func() hash.Hash
}

// Defaults used for when the input doesn't specify
var (
	DefaultSaltSize = 16            // Default number of bytes in salt
	DefaultKeySize  = 32            // Default number of bytes for derived key
	DefaultMethod   = "HMAC-SHA256" // Default PRF for PBKDF2
	DefaultRounds   = 100000        // Default number of PBKDF2 rounds
)

// String prints the Challenge without the password

// DeriveKeyWithLength calculates the key of size bytes using PBKDF2
func (c *Challenge) DeriveKeyWithLength(size int) ([]byte, error) {
	c.KeyLen = size

	switch c.PRF {
	case "HMAC-SHA256":
		c.prfHash = sha256.New
	default:
		return nil, errors.New("unknown PRF")
	}

	if c.KeyLen > c.prfHash().Size() {
		fmt.Fprintf(os.Stderr, "PBKDF2 sucks at stretching: keylen %d > hash size %d", c.KeyLen, c.prfHash().Size())
	}

	c.Dk = pbkdf2.Key([]byte(c.Pwd), c.Salt, c.Rounds, c.KeyLen, c.prfHash)
	c.DkHex = hex.EncodeToString(c.Dk)
	return c.Dk, nil
}

// DeriveKey calculates key of default size using PBKDF2
func (c *Challenge) DeriveKey() ([]byte, error) {
	if c.KeyLen < 16 {
		c.KeyLen = DefaultKeySize
	}
	return c.DeriveKeyWithLength(c.KeyLen)
}

// FleshOut takes what exists within a challenge and fills in defaults and other
// fields based on what is there.
func (c *Challenge) FleshOut() {
	if c.Rounds == 0 {
		c.Rounds = DefaultRounds
	}
	if c.KeyLen == 0 {
		c.KeyLen = DefaultKeySize
	}
	if len(c.PRF) == 0 {
		c.PRF = DefaultMethod
	}

	switch {
	case c.Salt == nil && len(c.SaltHex) == 0:
		c.Salt = make([]byte, DefaultSaltSize)
		rand.Read(c.Salt)
		fallthrough
	case c.Salt != nil && len(c.SaltHex) == 0:
		c.SaltHex = hex.EncodeToString(c.Salt)
	case c.Salt == nil && len(c.SaltHex) > 0:
		c.Salt, _ = hex.DecodeString(c.SaltHex)
	}

	// unlike a missing salt, we do not derive a key until explicitly told to
	switch {
	case c.Dk != nil && len(c.DkHex) == 0:
		c.SaltHex = hex.EncodeToString(c.Dk)
	case c.Dk == nil && len(c.DkHex) > 0:
		c.Dk, _ = hex.DecodeString(c.DkHex)
	}

	if len(c.ID) == 0 {
		// create an ID from the salt. (Let's hope all salts are unique)
		// By taking a multiple of three bytes, we get base64 encoding without padding
		c.ID = base64.StdEncoding.EncodeToString(c.Salt[0:9])
	}
}

func (c *Challenge) String() string {
	s, err := json.MarshalIndent(c, "", "\t")
	if err != nil {
		return fmt.Sprintf("ERROR: couldn't marshal: %s", err)
	}
	return string(s)
}
