// chacha20.go - public domain ChaCha20 encryption/decryption.
// I, Ron Charlton, used clang -E to preprocess chacha-ref.c from
// <https://cr.yp.to/chacha.html> to produce a prototype chacha20.go file,
// then hand-edited it to make true Go source code. I added
// New, NewWithKeyIv and SetRounds, and made the default rounds 20.
//
// Public domain is per <https://creativecommons.org/publicdomain/zero/1.0/>
//
// I tested chacha20.go by encrypting a 21KB+ text file with chacha-ref.c
// and chacha20.go and comparing the two results, they were identical.
// Rounds must be identical so the comparison can succeed.
//
// From the C file (chacha-ref.c):
//		chacha-ref.c version 20080118
//		D. J. Bernstein
//		Public domain.
//
// This file (chacha20.go):
//		Author:  Ron Charlton <Ron[@]RonCharlton[.]org>
//		Created: 2022-08-28
//		Public domain.
//
// Type byte must be an alias for uint8.
//
// Example use (encrypt a file to another file):
//		// 32-byte key and 8-byte iv assumed.
//		// (error checks omitted)
//		b, err := os.ReadFile("myfile")
//		ctx := chacha20.NewWithKeyIv(key, iv)
//		ctx.Encrypt(b, b)
//		err = os.WriteFile("myfile.encrypted", b, 0644)
//
// ChaCha20 Encrypt on a 3.2 GHz M1 Mac mini (go test -bench=.):
//
//	 Rounds	 	 MB/s
//	 ------		 ----
//	    8		 633
//	   12		 507
//	   20		 364
//
// $Id: chacha20.go,v 2.18 2022-09-05 16:34:46-04 ron Exp $
////

package chacha20

import (
	"encoding/binary"
	"log"
)

// defaultRounds can be 8, 12 or 20.  Lower numbers are likely less secure.
// Higher numbers consume more compute time.  ChaCha20 requires 20.
const defaultRounds = 20

func salsa20_wordtobyte(input []uint32, rounds int) (output [64]byte) {
	var x [16]uint32
	var i int

	for i = 0; i < 16; i++ {
		x[i] = input[i]
	}

	for i = rounds; i > 0; i -= 2 {
		x[0] = x[0] + x[4]
		x[12] = ((x[12] ^ x[0]) << 16) | ((x[12] ^ x[0]) >> (32 - 16))
		x[8] = x[8] + x[12]
		x[4] = ((x[4] ^ x[8]) << 12) | ((x[4] ^ x[8]) >> (32 - 12))
		x[0] = x[0] + x[4]
		x[12] = ((x[12] ^ x[0]) << 8) | ((x[12] ^ x[0]) >> (32 - 8))
		x[8] = x[8] + x[12]
		x[4] = ((x[4] ^ x[8]) << 7) | ((x[4] ^ x[8]) >> (32 - 7))

		x[1] = x[1] + x[5]
		x[13] = ((x[13] ^ x[1]) << 16) | ((x[13] ^ x[1]) >> (32 - 16))
		x[9] = x[9] + x[13]
		x[5] = ((x[5] ^ x[9]) << 12) | ((x[5] ^ x[9]) >> (32 - 12))
		x[1] = x[1] + x[5]
		x[13] = ((x[13] ^ x[1]) << 8) | ((x[13] ^ x[1]) >> (32 - 8))
		x[9] = x[9] + x[13]
		x[5] = ((x[5] ^ x[9]) << 7) | ((x[5] ^ x[9]) >> (32 - 7))

		x[2] = x[2] + x[6]
		x[14] = ((x[14] ^ x[2]) << 16) | ((x[14] ^ x[2]) >> (32 - 16))
		x[10] = x[10] + x[14]
		x[6] = ((x[6] ^ x[10]) << 12) | ((x[6] ^ x[10]) >> (32 - 12))
		x[2] = x[2] + x[6]
		x[14] = ((x[14] ^ x[2]) << 8) | ((x[14] ^ x[2]) >> (32 - 8))
		x[10] = x[10] + x[14]
		x[6] = ((x[6] ^ x[10]) << 7) | ((x[6] ^ x[10]) >> (32 - 7))

		x[3] = x[3] + x[7]
		x[15] = ((x[15] ^ x[3]) << 16) | ((x[15] ^ x[3]) >> (32 - 16))
		x[11] = x[11] + x[15]
		x[7] = ((x[7] ^ x[11]) << 12) | ((x[7] ^ x[11]) >> (32 - 12))
		x[3] = x[3] + x[7]
		x[15] = ((x[15] ^ x[3]) << 8) | ((x[15] ^ x[3]) >> (32 - 8))
		x[11] = x[11] + x[15]
		x[7] = ((x[7] ^ x[11]) << 7) | ((x[7] ^ x[11]) >> (32 - 7))

		x[0] = x[0] + x[5]
		x[15] = ((x[15] ^ x[0]) << 16) | ((x[15] ^ x[0]) >> (32 - 16))
		x[10] = x[10] + x[15]
		x[5] = ((x[5] ^ x[10]) << 12) | ((x[5] ^ x[10]) >> (32 - 12))
		x[0] = x[0] + x[5]
		x[15] = ((x[15] ^ x[0]) << 8) | ((x[15] ^ x[0]) >> (32 - 8))
		x[10] = x[10] + x[15]
		x[5] = ((x[5] ^ x[10]) << 7) | ((x[5] ^ x[10]) >> (32 - 7))

		x[1] = x[1] + x[6]
		x[12] = ((x[12] ^ x[1]) << 16) | ((x[12] ^ x[1]) >> (32 - 16))
		x[11] = x[11] + x[12]
		x[6] = ((x[6] ^ x[11]) << 12) | ((x[6] ^ x[11]) >> (32 - 12))
		x[1] = x[1] + x[6]
		x[12] = ((x[12] ^ x[1]) << 8) | ((x[12] ^ x[1]) >> (32 - 8))
		x[11] = x[11] + x[12]
		x[6] = ((x[6] ^ x[11]) << 7) | ((x[6] ^ x[11]) >> (32 - 7))

		x[2] = x[2] + x[7]
		x[13] = ((x[13] ^ x[2]) << 16) | ((x[13] ^ x[2]) >> (32 - 16))
		x[8] = x[8] + x[13]
		x[7] = ((x[7] ^ x[8]) << 12) | ((x[7] ^ x[8]) >> (32 - 12))
		x[2] = x[2] + x[7]
		x[13] = ((x[13] ^ x[2]) << 8) | ((x[13] ^ x[2]) >> (32 - 8))
		x[8] = x[8] + x[13]
		x[7] = ((x[7] ^ x[8]) << 7) | ((x[7] ^ x[8]) >> (32 - 7))

		x[3] = x[3] + x[4]
		x[14] = ((x[14] ^ x[3]) << 16) | ((x[14] ^ x[3]) >> (32 - 16))
		x[9] = x[9] + x[14]
		x[4] = ((x[4] ^ x[9]) << 12) | ((x[4] ^ x[9]) >> (32 - 12))
		x[3] = x[3] + x[4]
		x[14] = ((x[14] ^ x[3]) << 8) | ((x[14] ^ x[3]) >> (32 - 8))
		x[9] = x[9] + x[14]
		x[4] = ((x[4] ^ x[9]) << 7) | ((x[4] ^ x[9]) >> (32 - 7))
	}

	for i = 0; i < 16; i++ {
		x[i] += input[i]
		binary.LittleEndian.PutUint32(output[4*i:], x[i])
	}

	return
}

// ChaCha20_ctx contains state information for a ChaCha20 context.
type ChaCha20_ctx struct {
	input  []uint32
	rounds int
}

// New allocates a new ChaCha20 context.  The caller must use KeySetup
// and IvSetup to set up the new context.  The default number of rounds
// is 20.
func New() *ChaCha20_ctx {
	return &ChaCha20_ctx{
		input:  make([]uint32, 16),
		rounds: defaultRounds}
}

// NewWithKeyIv allocates a new ChaCha20 context and for convenience sets
// up the new context with the caller's key and iv.  The default number
// of rounds is 20.
func NewWithKeyIv(key, iv []byte) (ctx *ChaCha20_ctx) {
	ctx = New()
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	return
}

// SetRounds sets the number of rounds used by Encrypt, Decrypt and
// Keystream for a ChaCha20 context.  The valid values for r are
// 8, 12 and 20. SetRounds ignores any other value.  The default number
// of rounds is 20 for ChaCha20.  Fewer rounds may be less secure.  More
// rounds consume more compute time.  ChaCha8 requires 8, ChaCha12 requires
// 12 and ChaCha20 requires 20.
func (x *ChaCha20_ctx) SetRounds(r int) {
	if r == 8 || r == 12 || r == 20 {
		x.rounds = r
	}
}

var sigma = []byte("expand 32-byte k")
var tau = []byte("expand 16-byte k")

// KeySetup sets up ChaCha20 context x with key k.  KeySetup panics if len(k)
// is not 16 or 32. A key length of 32 is recommended.
func (x *ChaCha20_ctx) KeySetup(k []byte) {
	var constants []byte
	kbytes := len(k)

	if kbytes != 16 && kbytes != 32 {
		log.Panicf("ChaCha20.KeySetup: invalid key length; must be 16 "+
			"or 32 bytes (is %d).", kbytes)
	}

	x.input[4] = binary.LittleEndian.Uint32(k[0:])
	x.input[5] = binary.LittleEndian.Uint32(k[4:])
	x.input[6] = binary.LittleEndian.Uint32(k[8:])
	x.input[7] = binary.LittleEndian.Uint32(k[12:])

	if kbytes == 32 {
		k = k[16:]
		constants = sigma
	} else {
		constants = tau
	}

	x.input[8] = binary.LittleEndian.Uint32(k[0:])
	x.input[9] = binary.LittleEndian.Uint32(k[4:])
	x.input[10] = binary.LittleEndian.Uint32(k[8:])
	x.input[11] = binary.LittleEndian.Uint32(k[12:])
	x.input[0] = binary.LittleEndian.Uint32(constants[0:])
	x.input[1] = binary.LittleEndian.Uint32(constants[4:])
	x.input[2] = binary.LittleEndian.Uint32(constants[8:])
	x.input[3] = binary.LittleEndian.Uint32(constants[12:])
}

// IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
// It also sets the context's counter to 0.  IvSetup panics if len(iv) is not 8.
func (x *ChaCha20_ctx) IvSetup(iv []byte) {
	if len(iv) != 8 {
		log.Panicf("ChaCha20.IvSetup: invalid iv length; must be 8 "+
			"(is %d).", len(iv))
	}
	x.input[12] = 0
	x.input[13] = 0
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
}

// Encrypt puts ciphertext into c given plaintext m.  Any length is allowed
// for m.  The same memory may be used for m and c.  Encrypt panics if
// c is not at least as long as m.
func (x *ChaCha20_ctx) Encrypt(m, c []byte) {
	var i int
	bytes := len(m)

	if bytes == 0 {
		return
	}
	if len(c) < bytes {
		log.Panic("ChaCha20.Encrypt: insufficient space; c is shorter than m is.")
	}
	for {
		output := salsa20_wordtobyte(x.input, x.rounds)

		x.input[12] += 1
		if x.input[12] == 0 {
			x.input[13] += 1
			/* stopping at 2^70 bytes per nonce is user's responsibility */
			/* RonC: Generating 2^70 bytes would require 5.9e+12 years. */
		}
		if bytes <= 64 {
			for i = 0; i < bytes; i++ {
				c[i] = m[i] ^ output[i]
			}
			return
		}
		for i = 0; i < 64; i++ {
			c[i] = m[i] ^ output[i]
		}
		bytes -= 64
		c = c[64:]
		m = m[64:]
	}
}

// Decrypt puts plaintext into m given ciphertext c.  Any length is allowed
// for c.  The same memory may be used for c and m.  Decrypt panics if m is
// not at least as long as c.
func (x *ChaCha20_ctx) Decrypt(c, m []byte) {
	if len(m) < len(c) {
		log.Panic("ChaCha20.Decrypt: insufficient space; m is shorter than c is.")
	}
	x.Encrypt(c, m)
}

// Keystream fills stream with bytes from x's keystream.
func (x *ChaCha20_ctx) Keystream(stream []byte) {
	bytes := len(stream)
	for i := 0; i < bytes; i++ {
		stream[i] = 0
	}
	x.Encrypt(stream, stream)
}
