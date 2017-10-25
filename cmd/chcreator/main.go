package main

import (
	"encoding/hex"
	"fmt"

	"github.com/jpgoldberg/opchallenge/crackme"
	"github.com/jpgoldberg/opchallenge/dprng"

	"os"
)

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

	seed, _ := hex.DecodeString("5a463d81675b7373f4b5cc7768213664")
	drng, err := dprng.NewDPRNG(seed)
	if err != nil {
		fmt.Fprint(os.Stderr, "Couldn't create RNG: $v\n", err)
		os.Exit(1)
	}
	challenges := make([]crackme.Challenge, 20)
	for kind, pwds := range pwdsByKind {
		for _, pwd := range pwds {
			c := crackme.Challenge{Rounds: rounds, PrfName: "HMAC-SHA256", Hint: kind, Pwd: pwd}
			if kind == "sample" {
				c.Hint = fmt.Sprintf("\"%s\"", pwd)
			}
			c.Salt = make([]byte, saltLen)
			_, err := drng.Read(c.Salt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Couldn't read salt: %v\n", err)
				os.Exit(1)
			}

			_, err = c.DeriveKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Couldn't derive key: %v\n", err)
				os.Exit(1)
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
