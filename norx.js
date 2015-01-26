// JavaScript implementation of the NORX authenticated stream cipher.
// Written by Nadim Kobeissi, 2015 <nadim@nadim.computer>.
// License: CC0.

var NORX = {}

;(function() {

'use strict';

var INFO = [
	'NORX.init: Parameter R set to default 4.',
	'NORX.init: Parameter A set to default 4.'
]

var ERROR = [
	'NORX: Uninitialized. Run NORX.init() first.',
	'NORX.init: Initialization failed.',
	'NORX.encrypt: Invalid key size.',
	'NORX.encrypt: Invalid nonce size.',
	'NORX.decrypt: Invalid key size.',
	'NORX.decrypt: Invalid nonce size.',
	'NORX.decrypt: Decryption failed.'
]

var PARAMS = {
	W: 32,
	D: 1,
	M: 0xFFFFFFFF,
	U: [
		0x243F6A88, 0x85A308D3,
		0x13198A2E, 0x03707344,
		0x254F537A, 0x38531D48,
		0x839C6E83, 0xF97A3AE5,
		0x8C91D88C, 0x11EAFB59
	],
	R: 0,
	A: 0
}

var OPER = {
	H: function(a, b) {
		return ((a ^ b) ^ ((a & b) << 1))
	},
	ROTR: function(a, r) {
		return ((a >>> r) | (a << (PARAMS.W - r)))
	},
	G: function(S, a, b, c, d) {
		S[a] = OPER.H(S[a], S[b])
		S[d] = OPER.ROTR(S[a] ^ S[d],  8)
		S[c] = OPER.H(S[c], S[d])
		S[b] = OPER.ROTR(S[b] ^ S[c], 11)
		S[a] = OPER.H(S[a], S[b])
		S[d] = OPER.ROTR(S[a] ^ S[d], 16)
		S[c] = OPER.H(S[c], S[d])
		S[b] = OPER.ROTR(S[b] ^ S[c], 31)
	},
	F: function(r, S) {
		for (var i = 0; i < r; i++) {
			OPER.G(S, 0, 4,  8, 12)
			OPER.G(S, 1, 5,  9, 13)
			OPER.G(S, 2, 6, 10, 14)
			OPER.G(S, 3, 7, 11, 15)
			OPER.G(S, 0, 5, 10, 15)
			OPER.G(S, 1, 6, 11, 12)
			OPER.G(S, 2, 7,  8, 13)
			OPER.G(S, 3, 4,  9, 14)
		}
	}
}

var isNumber = function(x) {
	return typeof x === 'number'
}

var isDefined = function(x) {
	return typeof x !== 'undefined'
}

var initializeState = function(k, n) {
	var S = new Uint32Array(16)
	S[ 0] = PARAMS.U[0]
	S[ 1] = n[0]
	S[ 2] = n[1]
	S[ 3] = PARAMS.U[1]
	S[ 4] = k[0]
	S[ 5] = k[1]
	S[ 6] = k[2]
	S[ 7] = k[3]
	S[ 8] = PARAMS.U[2]
	S[ 9] = PARAMS.U[3]
	S[10] = PARAMS.U[4]
	S[11] = PARAMS.U[5]
	S[12] = PARAMS.U[6]
	S[13] = PARAMS.U[7]
	S[14] = PARAMS.U[8]
	S[15] = PARAMS.U[9]
	S[14] ^= (
		(PARAMS.R << 26) ^
		(PARAMS.D << 18) ^
		(PARAMS.W << 10) ^
		(PARAMS.A)
	)
	OPER.F(PARAMS.R, S)
	S[15] ^= 0x00000001
	OPER.F(PARAMS.R, S)
	return S
}

var applyPad = function(bytes) {
	var pad = new Uint32Array(
		bytes.length + (10 - (bytes.length % 10))
	)
	pad.set(bytes, 0)
	pad[  bytes.length] = 0x00000001
	pad[pad.length - 1] = 0x80000000
	return pad
}

var selfTest = function() {
	var k = new Uint32Array([
		0x00112233, 0x44556677,
		0x8899AABB, 0xCCDDEEFF
	])
	var n = new Uint32Array([
		0xFFFFFFFF, 0xFFFFFFFF
	])
	var h = new Uint32Array([
		0x10000002, 0x30000004
	])
	var p = new Uint32Array([
		0x80000007, 0x60000005,
		0x40000003, 0x20000001
	])
	var t = new Uint32Array([])
	var e = NORX.encrypt(k, n, h, p, t)
	var d = NORX.decrypt(
		k, n, h, e.c, t, e.t
	)
	if (
		(e.c[0] === 0x1F8F35CD) &&
		(e.c[1] === 0xCAFA2A38) &&
		(e.c[2] === 0x724C1417) &&
		(e.c[3] === 0x228732CA) &&
		(e.t[0] === 0x7702CA8A) &&
		(e.t[1] === 0xE8BA5210) &&
		(e.t[2] === 0xFD9B73AD) &&
		(e.t[3] === 0xC0443A0D) &&
		(d.t    ===       true) &&
		(d.p[0] === 0x80000007) &&
		(d.p[1] === 0x60000005) &&
		(d.p[2] === 0x40000003) &&
		(d.p[3] === 0x20000001)
	) {
		return true
	}
	else {
		return false
	}
}

NORX.init = function(r, a) {
	PARAMS.R = 4
	PARAMS.A = PARAMS.W * 4
	if (!selfTest()) {
		throw new Error(ERROR[1])
		return false
	}
	PARAMS.R = 0
	if (isNumber(r) && ((r > 0) && (r < 64))) {
		PARAMS.R = r
	}
	else {
		PARAMS.R = 4
		console.info(INFO[0])
	}
	if (isNumber(a) && (a > 0) && (a <= (10 * PARAMS.W))) {
		PARAMS.A = PARAMS.W * a
	}
	else {
		PARAMS.A = PARAMS.W * 4
		console.info(INFO[1])
	}
	return true
}

NORX.encrypt = function(k, n, h, p, t) {
	var c   = new Uint32Array(p.length)
	var tag = new Uint32Array(PARAMS.A / PARAMS.W)
	if (!PARAMS.R || !PARAMS.A) {
		throw new Error(ERROR[0])
		return false
	}
	if (k.length !== (PARAMS.W / 8)) {
		throw new Error(ERROR[2])
		return false
	}
	if (n.length !== (PARAMS.W / 16)) {
		throw new Error(ERROR[3])
		return false
	}
	var S = initializeState(k, n)
	if (isDefined(h) && h.length) {
		h = applyPad(h)
		for (var i = 0; i < (h.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				S[j] ^= h[j + (i * 10)]
			}
			if (isDefined(p) && p.length) {
				S[15] ^= 0x00000002
			}
			else if (isDefined(t) && t.length) {
				S[15] ^= 0x00000004
			}
			else {
				S[15] ^= 0x00000008
			}
			OPER.F(PARAMS.R, S)
		}
	}
	if (isDefined(p) && p.length) {
		p = applyPad(p)
		for (var i = 0; i < (p.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				S[j]    ^= p[j + (i * 10)]
				c[j + (i * 10)]  = S[j]
			}
			if (isDefined(t) && t.length) {
				S[15] ^= 0x00000004
			}
			else {
				S[15] ^= 0x00000008
			}
			OPER.F(PARAMS.R, S)
		}
	}
	if (isDefined(t) && t.length) {
		t = applyPad(t)
		for (var i = 0; i < (t.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				S[j] ^= t[j + (i * 10)]
			}
			S[15] ^= 0x00000008
			OPER.F(PARAMS.R, S)
		}
	}
	(function() {
		OPER.F(PARAMS.R, S)
		tag.set(S.subarray(0, PARAMS.A / PARAMS.W), 0)
	})()
	return {
		c: c,
		t: tag
	}
}

NORX.decrypt = function(k, n, h, c, t, a) {
	var p   = new Uint32Array(c.length)
	var tag = new Uint32Array(PARAMS.A / PARAMS.W)
	if (!PARAMS.R || !PARAMS.A) {
		throw new Error(ERROR[0])
		return false
	}
	if (k.length !== (PARAMS.W / 8)) {
		throw new Error(ERROR[2])
		return false
	}
	if (n.length !== (PARAMS.W / 16)) {
		throw new Error(ERROR[3])
		return false
	}
	var S = initializeState(k, n)
	if (isDefined(h) && h.length) {
		h = applyPad(h)
		for (var i = 0; i < (h.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				S[j] ^= h[j + (i * 10)]
			}
			if (isDefined(c) && c.length) {
				S[15] ^= 0x00000002
			}
			else if (isDefined(t) && t.length) {
				S[15] ^= 0x00000004
			}
			else {
				S[15] ^= 0x00000008
			}
			OPER.F(PARAMS.R, S)
		}
	}
	if (isDefined(c) && c.length) {
		var cL = c.length
		c = applyPad(c)
		cL = 10 - (c.length - cL)
		for (var i = 0; i < (c.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				p[j + (i * 10)] = S[j] ^ c[j + (i * 10)]
				if (
					(i === (c.length / 10) - 1) &&
					(j >= cL)
				) {
					S[j] ^= c[j + (i * 10)]
				}
				else {
					S[j] = c[j + (i * 10)]
				}
			}
			if (t.length) {
				S[15] ^= 0x00000004
			}
			else {
				S[15] ^= 0x00000008
			}
			OPER.F(PARAMS.R, S)
		}
	}
	if (isDefined(t) && t.length) {
		t = applyPad(t)
		for (var i = 0; i < (t.length / 10); i++) {
			for (var j = 0; j < 10; j++) {
				S[j] ^= t[j + (i * 10)]
			}
			S[15] ^= 0x00000008
			OPER.F(PARAMS.R, S)
		}
	}
	(function() {
		OPER.F(PARAMS.R, S)
		tag.set(S.subarray(0, PARAMS.A / PARAMS.W), 0)
	})()
	return (function() {
		if (a.length !== tag.length) {
			return false
		}
		var comp = 0
		for (var i = 0; i < tag.length; i++) {
			comp |= a[i] ^ tag[i]
		}
		if (comp === 0) {
			return {
				p: p,
				t: true
			}
		}
		else {
			return {
				p: new Uint32Array(),
				t: false
			}
		}
	})()
}

})()


NORX.init()
