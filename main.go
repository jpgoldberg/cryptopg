package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"hash"

	"golang.org/x/crypto/pbkdf2"
)

type Challange struct {
	Rounds, KeyLen     int
	Salt, Dk           []byte
	PrfName, Pwd, Hint string
	prf                func() hash.Hash
}

// String prints the Challange without the password
func (c Challange) String() string {
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

// DeriveKey calculates the key using PBKDF2
func (c *Challange) DeriveKey() ([]byte, error) {
	if c.KeyLen == 0 {
		c.KeyLen = 32
	}
	switch c.PrfName {
	case "HMAC-SHA256":
		c.prf = sha256.New
	default:
		return nil, errors.New("unknown PRF")
	}

	c.Dk = pbkdf2.Key([]byte(c.Pwd), c.Salt, c.Rounds, c.KeyLen, c.prf)
	return c.Dk, nil
}

func main() {
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

	challenges := make([]Challange, 20)
	for kind, pwds := range pwdsByKind {
		for _, pwd := range pwds {
			c := Challange{Rounds: rounds, PrfName: "HMAC-SHA256", Hint: kind}
			if kind == "sample" {
				c.Hint = fmt.Sprintf("\"%s\"", pwd)
			}
			c.Salt = make([]byte, saltLen)
			_, err := rand.Read(c.Salt)
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
