# An informal wordlist password cracking challenge

Jeffrey Goldberg <jeff@agilebits.com><br>

2017-10-24

This is very informal and just thrown together. It arose from various conversations of about the strengths of Diceware-like passwords. 1Password has a password generator that can produce such passwords from a list of 18328 words (as of today).

```
$ wc -l Resources/AgileWords.txt 
   18328 Resources/AgileWords.txt
$ date
Tue Oct 24 20:39:21 CDT 2017
```

## Why?

I have some estimates about how hard these are to crack, but would like to see people actually go at it and report results.

## What?

These all use PBKDF2-HMAC-SHA256 with 100000 rounds.

There are 11 challenges of varying difficulty plus three samples in which the answer (password) is given.

For each of the challenges you are told how many words comprise the password. The words are separated by spaces.

### Difficulty levels

The two word challenges should be easy to crack, and are offered so
that you can make sure that you can actually crack some of these. But
this should also be usable to see how many guesses per second you can
generate and how this all works out.

The three word challenges are where it gets interesting. I don't know
if enough people with the right gear will put in the time, electricity,
and cooling costs to crack these. But if someone does, it would be
fantastic to learn how it happened.

I would be extremely surprised if anyone without _very_ deep pockets
would crack a four word password, but I am open to being surprised.

I believe that five words or more are currently unassailable by anyone. 
But again, my estimates may be wrong.

## Prizes?

None. Sorry. I just cooked these up and haven't talked to those who
control the purse strings about prizes. Nor is this really being
presented as a formal challenge in a way that would be provably fair to all participants.

## Word list

I haven't sought permission internally to publish our wordlist, so you
will have to extract it from one of our clients. It shouldn't be hard
to find. Once you find it, you may use it for this exercise or for
further research, but do not publish it.

## This is not the 1Password KDF!

Just a note that the KDF used in 1Password is different than this.
There are additional protections to make sure that data stolen from our
servers cannot be cracked. See our [security white
paper](https://1password.com/teams/white-paper/) for its description of
Two-Secret Key Derivation (2SKD), which ensures that user data which
AgileBits holds cannot be cracked.

However, if data is stolen from a user's machine device instead of from
ours, the crackability of that data is similar to what is presented
here.

## Algorithm details

Excerpts from the golang code I used to create these challenges:

```golang
// Challenge has details for each PBKDF2 challenges
type Challenge struct {
	Rounds, KeyLen     int
	Salt, Dk           []byte
	PrfName, Pwd, Hint string
	prf                func() hash.Hash
}
```

```golang
/ DeriveKeyWithLength calculates the key of size bytes using PBKDF2
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
```

## Challenge records

PRF: The PRF used by PBKDF2
Rounds: The number of PBKDF2 iterations
Hint: This tells you either how many words the password is or it gives 
	the password in quotes.
Salt: A hex representation of the salt used for PBKDF2
DKey: A hex representation of derived key.


## Challenges

### Samples

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	"123456"
	Salt:	e72314f3acedfea0127ef33081a2cc13
	DKey:	b242c2b4391c7b1004cafc53cedd4908272f6c1feb3e4788e1c5c275bc13695f

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	"Password1"
	Salt:	9f63da94996bbafafe5c6ae676e8703b
	DKey:	295005cd1f40de46dd91c9caed4977066cae22919973510819f1b2026545300b

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	"noose artless yield"
	Salt:	77826918c70d6decf6591543a84eae32
	DKey:	d66dd599330b2b7be779fedd27d0c58e2c012317a3c6a19d08e451efba0e2b75

### Actual challenges

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	two word
	Salt:	7f84bc8a721b6aabcd0e380e90b300b8
	DKey:	cb0a7b210ac0cb3d4714abaf5f269f09959f1cca661c43bd7cef604912d65972

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	two word
	Salt:	9c2c1e0f85cb8d8e194015f9f4e3bbee
	DKey:	c2fb1b883e346e4d2aa9273a96b9e247812049039f8a2c1d4e7fc4bea1111925

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	two word
	Salt:	2509ddf810f110544554f72402ef77a5
	DKey:	2715e1c24cd99cbaf4d3ebb4373ac3d422a3cc2e5419cf7ea3ee753daeddafcb

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	three word
	Salt:	d50926c39c2f47b72cbc00ded073a87b
	DKey:	fdd83c9cb7f16c1ae9389d27ef03a049b9dcecb5a9422e684845d8d5c79ba4ad

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	three word
	Salt:	ad32793e47a45c102f0d2c07c4cde40d
	DKey:	c4c29d491bd2068a6d09a105bbd128bf49d2f286cc6f92f5ce5ff319767e259b

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	three word
	Salt:	d16bb863f71896051f4b26391cdd773f
	DKey:	110981e6dfda69cdc96280765a5d4cc2e608b1ddc7c0108bb313195d2698b9a4

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	four word
	Salt:	36596b9937f3c130152a7d63dea8b330
	DKey:	987564cf1f0029cb9411a7e1da83910c741aff26bff99a5b6cb317cad9edce88

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	four word
	Salt:	080cbfbdaa67f8ca4b2bdc80953ebbd5
	DKey:	98ef104953487ce679a043bc3739d9fe3ecf86b60cdf83051c335dda71bb986a

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	four word
	Salt:	dff200d9e646e9b06898ce9e1f4dee76
	DKey:	2e80b9364b6dd7b2295968bb8d9d65def9a4addf94eb1e815fe3dada01438444

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	five word
	Salt:	901c7b154af85a852065c1cc1eb0f903
	DKey:	30969ef2b39aa7a2a8a2d8c8cb8b03a6c63dc1ec2f2350144c51e808149de5fc

	PRF:	HMAC-SHA256
	Rounds:	100000
	Hint:	five word
	Salt:	dc0673763796a6f3a6e9085ed096c00b
	DKey:	036fcf6a1711e5f31c62d17880360f2007dc0dbdc8cb710490d42f8b78e4c967

