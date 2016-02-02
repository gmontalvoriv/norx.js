# `norx.js`
## JavaScript implementation of the [NORX32 authenticated stream cipher](https://norx.io).

### Status: :warning: Experimental! :warning:
Currently, `norx.js` provides:  

* An implementation of NORX32 (with default configuration NORX32-4-1).
* Encryption with authentication tag generation.
* Decryption with constant-time authentication verification.
* Self-testing with the NORX test vectors.

### Usage

1. First, initialize NORX using `NORX.init(r, a)`:
	1. `r` (optional `number`) sets number of rounds. Default: 4.
	2. `a` (optional `number`) sets number of words for authentication tag. Default: 4.
2. Encrypt using `NORX.encrypt(k, n, h, p, t)`:
	1. `k` (required `Uint32Array`) is the 128 bit encryption key.
	2. `n` (required `Uint32Array`) is the 64 bit nonce.
	3. `h` (required `Uint32Array`) is the header (can be empty).
	4. `p` (required `Uint32Array`) is the payload (can be empty).
	5. `t` (required `Uint32Array`) is the trailer (can be empty).
3. `NORX.encrypt` will return an object containing:
	1. `c` (`Uint32Array`) the ciphertext.
	2. `t` (`Uint32Array`) the authentication tag.
4. Decrypt using `NORX.decrypt(k, n, h, c, t, a)`:
	1. `k` (required `Uint32Array`) is the 128 bit encryption key.
	2. `n` (required `Uint32Array`) is the 64 bit nonce.
	3. `h` (required `Uint32Array`) is the header (can be empty).
	4. `c` (required `Uint32Array`) is the ciphertext (can be empty).
	5. `t` (required `Uint32Array`) is the trailer (can be empty).
	6. `a` (required `Uint32Array`) is the authentication tag generated on encryption.
5. `NORX.decrypt` will return an object containing:
	1. `p` (`Uint32Array`) the plaintext, or empty in case of failure.
	2. `t` (`boolean`) whether authenticated decryption was successful.

### About
Written by Nadim Kobeissi, 2015 <nadim@nadim.computer>.  
License: CC0.

[NORX](https://norx.io) was invented by:

* Jean-Philippe Aumasson
* Philipp Jovanovic
* Samuel Neves
