package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	rounds := 10 ^ 5
	hashAlg := sha256.New
	saltLen := 16
	keyLen := 32

	var salt []byte

	// passwords should be read in externally, but now just putting them here
	pwds := []string{"123456", "Password1",
		"cadence upsilon", "seeming macaroni", "enact sediment",
		"gaur militia mince", "devote nuisance inseam", "nothing impiety accrue",
		"divulge clasp resent derelict", "inundate grunt sugar image", "planned cuckoo motor disburse",
		"windburn headrest crepe curdle bodily", "walrus glom armchair mad untried"}

	for _, pwd := range pwds {

		salt = make([]byte, saltLen)
		_, err := rand.Read(salt)
		if err != nil {
			fmt.Println("error:", err)
			return
		}

		dk := pbkdf2.Key([]byte(pwd), salt, rounds, keyLen, hashAlg)

		fmt.Println("\nsalt:", base64.URLEncoding.EncodeToString(salt))
		fmt.Println("Derived key:", base64.URLEncoding.EncodeToString(dk))
	}

}
