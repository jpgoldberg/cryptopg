package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	// "github.com/jpgoldberg/opchallenge/dprng"
)

// Challenge has details for each PBKDF2 challenges
type Challenge struct {
	Rounds, KeyLen     int
	Salt, Dk           []byte
	PrfName, Pwd, Hint string
	prf                func() hash.Hash
}

// TestVector is for challenges with Expected values
type TestVector struct {
	Challenge
	Expected string
}

// Pass checks of Dk is Expected
func (t TestVector) Pass() bool {
	if t.Dk == nil {
		t.DeriveKey()
	}
	e, _ := hex.DecodeString(t.Expected)
	if bytes.Compare(t.Dk, e) == 0 {
		return true
	}
	return false
}

var set5 = TestVector{
	Challenge: Challenge{
		Rounds:  4096,
		KeyLen:  40,
		Salt:    []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
		PrfName: "HMAC-SHA256",
		Pwd:     "passwordPASSWORDpassword",
		Hint:    "Set 5 https://github.com/ircmaxell/quality-checker/blob/master/tmp/gh_18/PHP-PasswordLib-master/test/Data/Vectors/pbkdf2-draft-josefsson-sha256.test-vectors",
		prf:     sha256.New,
		Dk:      nil,
	},
	// 348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9
	// From http://stackoverflow.com/a/5136918/1304076
	Expected: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
}

// String prints the Challenge without the password
func (c Challenge) String() string {
	if c.PrfName == "" {
		return ""
	}
	r := fmt.Sprintf("PRF:\t%s\n", c.PrfName)
	r += fmt.Sprintf("Rounds:\t%d\n", c.Rounds)
	if c.Hint != "" {
		r += fmt.Sprintf("Hint:\t%s\n", c.Hint)
	}
	if c.Salt != nil {
		r += fmt.Sprintf("Salt:\t%s\n", hex.EncodeToString(c.Salt))
	}
	if c.Dk != nil {
		r += fmt.Sprintf("DKey:\t%s\n", hex.EncodeToString(c.Dk))
	}
	return r
}

// String for test vector challenge
func (t TestVector) String() string {
	if t.Dk == nil {
		t.DeriveKey()
	}
	r := fmt.Sprintf("Passwd:\t\"%s\"\n", t.Pwd)
	r += t.Challenge.String()
	r += fmt.Sprintf("Expect:\t%s\n", t.Expected)
	r += fmt.Sprintf("Passes:\t%v\n", t.Pass())

	return r
}

// DeriveKeyWithLength calculates the key of size bytes using PBKDF2
func (c *Challenge) DeriveKeyWithLength(size int) ([]byte, error) {
	c.KeyLen = size

	switch c.PrfName {
	case "HMAC-SHA256":
		c.prf = sha256.New
	default:
		return nil, errors.New("unknown PRF")
	}

	c.Dk = pbkdf2.Key([]byte(c.Pwd), c.Salt, c.Rounds, c.KeyLen, c.prf)
	return c.Dk, nil
}

// DeriveKey calculates key of default size using PBKDF2
func (c *Challenge) DeriveKey() ([]byte, error) {
	length := 32
	if c.KeyLen == 0 {
		c.KeyLen = length
	}
	return c.DeriveKeyWithLength(c.KeyLen)
}

func main() {
	fmt.Println(set5) // our test vector

	rounds := 100000
	saltLen := 16

	// wFilePath := "Resources/AgileWords.txt"

	pwdsByKind := make(map[string][]string, 5)

	// passwords should be read in externally, but now just putting them here
	pwdsByKind["sample"] = []string{"123456", "Password1", "noose artless yield"}
	pwdsByKind["two word"] = []string{"cadence upsilon", "seeming macaroni", "enact sediment"}
	pwdsByKind["three word"] = []string{"gaur militia mince", "devote nuisance inseam", "nothing impiety accrue"}
	pwdsByKind["four word"] = []string{"divulge clasp resent derelict", "inundate grunt sugar image", "planned cuckoo motor disburse"}
	pwdsByKind["five word"] = []string{"windburn headrest crepe curdle bodily", "walrus glom armchair mad untried"}

	seed, _ := hex.DecodeString("5a463d81675b7373f4b5cc7768213664")
	drng := NewDPRNG(seed)
	challenges := make([]Challenge, 20)
	for kind, pwds := range pwdsByKind {
		for _, pwd := range pwds {
			c := Challenge{Rounds: rounds, PrfName: "HMAC-SHA256", Hint: kind}
			if kind == "sample" {
				c.Hint = fmt.Sprintf("\"%s\"", pwd)
			}
			c.Salt = make([]byte, saltLen)
			_, err := drng.Read(c.Salt)
			if err != nil {
				fmt.Println("error:", err)
				return
			}

			_, err = c.DeriveKey()
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			challenges = append(challenges, c)
		}
	}
	for _, c := range challenges {
		if c.PrfName != "" {
			fmt.Println(c)
		}
	}

}
