# Password cracking challenges

These are tools for creating password cracking challenges which are useful in guaging the strength of 1Password Master Passwords under the assumption that the the attacker has captured the users Secret Key.

We, at AgileBits, want to get a sense of how much time and effort it takes to guess certain sorts of Master Passwords. Thus, we want the attacker to succeed in some cases so that we can learn how long such attacks case. That is, most of these challenges are designed to be conquored. 

## Attacker model

The challenges here do not model what an attacker, Oscar, would face if he captured data from the 1Password server. The use of Two secret Key Derivation makes server-only data uncrackable. Instead the challenges are designed to approximate the case where Oscar has acquired 1Password data from a target's own system and has the Secret Key from that system. Only the Master Password needs to be guessed.

## Simple KDF

The current version does not model the full details of the 1Passowrd KDF, but it does include the substance of it for these purposes. The relevant part of the KDF is salted PBKDF2-HMAC-SHA256 with 100,000 iterations.

