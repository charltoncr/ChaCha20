// chacha20.go - public domain ChaCha20 encryption/decryption.
// I, Ron Charlton, used clang -E to preprocess chacha-ref.c from
// <https://cr.yp.to/chacha.html> to produce a prototype chacha20.go file,
// then hand-edited it to make true Go source code. I added
// New, Seek, Read and SetRounds, and made the default rounds 20.
//
// Public domain is per <https://creativecommons.org/publicdomain/zero/1.0/>
//
// chacha20.go was tested by encrypting a 21KB+ text file with chacha-ref.c
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
//		ctx := chacha20.New(key, iv)
//		ctx.Encrypt(b, b)
//		err = os.WriteFile("myfile.encrypted", b, 0644)
//
// chacha20.go v3.5 Encrypt on a 3.2 GHz M1 Mac mini (go test -bench=.):
//
//	 Rounds	 	 MB/s
//	 ------		 ----
//	    8		 745
//	   12		 602
//	   20		 442
//
// $Id: chacha20.go,v 4.4 2022-09-14 09:35:34-04 ron Exp $
////

// Package chacha20 provides public domain ChaCha20 encryption and decryption.
// Package chacha20 is derived from public domain chacha-ref.c at
// <https://cr.yp.to/chacha.html>.
package chacha20

import (
	"encoding/binary"
)

// defaultRounds can be 8, 12 or 20.  Lower numbers are likely less secure.
// Higher numbers consume more compute time.  ChaCha20 requires 20.
const defaultRounds = 20

// Using individual variables instead of an array provides 32% faster code.
func salsa20_wordtobyte(input []uint32, rounds int, output []byte) {
	var t uint32
	var z int
	var a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p uint32

	a = input[0]
	b = input[1]
	c = input[2]
	d = input[3]
	e = input[4]
	f = input[5]
	g = input[6]
	h = input[7]
	i = input[8]
	j = input[9]
	k = input[10]
	l = input[11]
	m = input[12]
	n = input[13]
	o = input[14]
	p = input[15]

	for z = rounds; z > 0; z -= 2 {
		a += e
		t = m ^ a
		m = (t << 16) | (t >> (32 - 16))
		i += m
		t = e ^ i
		e = (t << 12) | (t >> (32 - 12))
		a += e
		t = m ^ a
		m = (t << 8) | (t >> (32 - 8))
		i += m
		t = e ^ i
		e = (t << 7) | (t >> (32 - 7))

		b += f
		t = n ^ b
		n = (t << 16) | (t >> (32 - 16))
		j += n
		t = f ^ j
		f = (t << 12) | (t >> (32 - 12))
		b += f
		t = n ^ b
		n = (t << 8) | (t >> (32 - 8))
		j += n
		t = f ^ j
		f = (t << 7) | (t >> (32 - 7))

		c += g
		t = o ^ c
		o = (t << 16) | (t >> (32 - 16))
		k += o
		t = g ^ k
		g = (t << 12) | (t >> (32 - 12))
		c += g
		t = o ^ c
		o = (t << 8) | (t >> (32 - 8))
		k += o
		t = g ^ k
		g = (t << 7) | (t >> (32 - 7))

		d += h
		t = p ^ d
		p = (t << 16) | (t >> (32 - 16))
		l += p
		t = h ^ l
		h = (t << 12) | (t >> (32 - 12))
		d += h
		t = p ^ d
		p = (t << 8) | (t >> (32 - 8))
		l += p
		t = h ^ l
		h = (t << 7) | (t >> (32 - 7))

		a += f
		t = p ^ a
		p = (t << 16) | (t >> (32 - 16))
		k += p
		t = f ^ k
		f = (t << 12) | (t >> (32 - 12))
		a += f
		t = p ^ a
		p = (t << 8) | (t >> (32 - 8))
		k += p
		t = f ^ k
		f = (t << 7) | (t >> (32 - 7))

		b += g
		t = m ^ b
		m = (t << 16) | (t >> (32 - 16))
		l += m
		t = g ^ l
		g = (t << 12) | (t >> (32 - 12))
		b += g
		t = m ^ b
		m = (t << 8) | (t >> (32 - 8))
		l += m
		t = g ^ l
		g = (t << 7) | (t >> (32 - 7))

		c += h
		t = n ^ c
		n = (t << 16) | (t >> (32 - 16))
		i += n
		t = h ^ i
		h = (t << 12) | (t >> (32 - 12))
		c += h
		t = n ^ c
		n = (t << 8) | (t >> (32 - 8))
		i += n
		t = h ^ i
		h = (t << 7) | (t >> (32 - 7))

		d += e
		t = o ^ d
		o = (t << 16) | (t >> (32 - 16))
		j += o
		t = e ^ j
		e = (t << 12) | (t >> (32 - 12))
		d += e
		t = o ^ d
		o = (t << 8) | (t >> (32 - 8))
		j += o
		t = e ^ j
		e = (t << 7) | (t >> (32 - 7))
	}

	a += input[0]
	binary.LittleEndian.PutUint32(output[4*0:], a)
	b += input[1]
	binary.LittleEndian.PutUint32(output[4*1:], b)
	c += input[2]
	binary.LittleEndian.PutUint32(output[4*2:], c)
	d += input[3]
	binary.LittleEndian.PutUint32(output[4*3:], d)
	e += input[4]
	binary.LittleEndian.PutUint32(output[4*4:], e)
	f += input[5]
	binary.LittleEndian.PutUint32(output[4*5:], f)
	g += input[6]
	binary.LittleEndian.PutUint32(output[4*6:], g)
	h += input[7]
	binary.LittleEndian.PutUint32(output[4*7:], h)
	i += input[8]
	binary.LittleEndian.PutUint32(output[4*8:], i)
	j += input[9]
	binary.LittleEndian.PutUint32(output[4*9:], j)
	k += input[10]
	binary.LittleEndian.PutUint32(output[4*10:], k)
	l += input[11]
	binary.LittleEndian.PutUint32(output[4*11:], l)
	m += input[12]
	binary.LittleEndian.PutUint32(output[4*12:], m)
	n += input[13]
	binary.LittleEndian.PutUint32(output[4*13:], n)
	o += input[14]
	binary.LittleEndian.PutUint32(output[4*14:], o)
	p += input[15]
	binary.LittleEndian.PutUint32(output[4*15:], p)
}

// ChaCha20_ctx contains state information for a ChaCha20 context.
type ChaCha20_ctx struct {
	input  []uint32
	output []byte
	next   int
	eof    bool
	rounds int
}

// ChaCha block length in bytes
const blockLen = 64

// New allocates a new ChaCha20 context and sets it up
// with the caller's key and iv.  The default number of rounds is 20.
func New(key, iv []byte) (ctx *ChaCha20_ctx) {
	ctx = &ChaCha20_ctx{
		input:  make([]uint32, 16),
		output: make([]byte, blockLen),
		next:   blockLen,
		rounds: defaultRounds,
	}
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	return
}

// SetRounds sets the number of rounds used by Encrypt, Decrypt, Read and
// Keystream for a ChaCha20 context.  The valid values for r are
// 8, 12 and 20. SetRounds ignores any other value.  ChaCha20's default number
// of rounds is 20.  Fewer rounds may be less secure.  More
// rounds consume more compute time.  ChaCha8 requires 8 rounds, ChaCha12
// requires 12 and ChaCha20 requires 20.
func (x *ChaCha20_ctx) SetRounds(r int) {
	if r == 8 || r == 12 || r == 20 {
		x.rounds = r
	}
}

// Seek moves x directly to 64-byte block number n in constant time.
func (x *ChaCha20_ctx) Seek(n uint64) {
	x.input[12] = uint32(n)
	x.input[13] = uint32(n >> 32)
	x.eof = false
	x.next = blockLen
}

var sigma = []byte("expand 32-byte k")
var tau = []byte("expand 16-byte k")

// KeySetup sets up ChaCha20 context x with key k.  KeySetup panics if len(k)
// is not 16 or 32. A key length of 32 is recommended.
func (x *ChaCha20_ctx) KeySetup(k []byte) {
	var constants []byte
	kbytes := len(k)

	if kbytes != 16 && kbytes != 32 {
		panic("chacha20.KeySetup: invalid key length; must be 16 or 32 bytes.")
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
	x.next = blockLen
}

// IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
// It also sets the context's counter to 0.  IvSetup panics if len(iv) is not 8.
func (x *ChaCha20_ctx) IvSetup(iv []byte) {
	if len(iv) != 8 {
		panic("chacha20.IvSetup: invalid iv length; must be 8.")
	}
	x.input[12] = 0
	x.input[13] = 0
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
	x.next = blockLen
}

// Encrypt puts ciphertext into c given plaintext m.  Any length is allowed
// for m.  The same memory may be used for m and c.  Encrypt panics if len(c) is
// less than len(m) or when the keystream is exhausted after producing 1.2
// zettabytes.
func (x *ChaCha20_ctx) Encrypt(m, c []byte) {
	var i int

	bytes := len(m)
	if bytes == 0 {
		return
	}
	if len(c) < bytes {
		panic("chacha20.Encrypt: insufficient space; c is shorter than m is.")
	}
	idx := x.next
	for i = 0; i < bytes; i++ {
		if idx >= blockLen {
			if x.eof {
				panic("chacha20: keystream is exhausted")
			}
			salsa20_wordtobyte(x.input, x.rounds, x.output)
			x.input[12] += 1
			if x.input[12] == 0 {
				x.input[13] += 1
				/* stopping at 2^70 bytes per nonce is user's responsibility */
				/* At 1 ns/block: 584+ years to exhaust the keystream.
				 * (2^70 bytes)/(64 bytes/ns)    RonC
				 */
				if x.input[13] == 0 {
					x.eof = true
				}
			}
			idx = 0
		}
		c[i] = m[i] ^ x.output[idx]
		idx++
	}
	x.next = idx
}

// Decrypt puts plaintext into m given ciphertext c.  Any length is allowed
// for c.  The same memory may be used for c and m.  Decrypt panics if len(m) is
// less than len(c) or when the keystream is exhausted after producing 1.2
// zettabytes.
func (x *ChaCha20_ctx) Decrypt(c, m []byte) {
	if len(m) < len(c) {
		panic("chacha20.Decrypt: insufficient space; m is shorter than c is.")
	}
	x.Encrypt(c, m)
}

// Keystream fills stream with cryptographically secure pseudorandom bytes
// from x's keystream when a random key and iv are used.  Keystream
// panics when the ChaCha keystream is exhausted after producing 1.2 zettabytes.
func (x *ChaCha20_ctx) Keystream(stream []byte) {
	bytes := len(stream)
	for i := 0; i < bytes; i++ {
		stream[i] = 0
	}
	x.Encrypt(stream, stream)
}

// See the comment in Encrypt() for why the error returned by Read is always nil.
// If the speed was 10 blocks/ns, the keystream wouldn't be exhausted for
// 58.4+ years, a long time for a process to run continuously.  10 blocks/ns
// is approximately 2,000 times faster than an Apple 3.2 GHz M1 Mac mini
// computer.  (With AES hardware acceleration the Mac mini produces about
// 1.3 bytes/ns with arc4random_buf.  This speed yields 28,778 years of non-
// stop processing before keystream exhaustion with ChaCha hardware
// acceleration similar to AES hardware acceleration in speed.)

// Read fills b with cryptographically secure pseudorandom bytes from x's
// keystream when a random key and iv are used. Read always returns
// len(b) and a nil error.  Read implements the io.Reader interface.
// Read panics when the keystream is exhausted after producing 1.2 zettabytes.
func (x *ChaCha20_ctx) Read(b []byte) (int, error) {
	bytes := len(b)
	for i := 0; i < bytes; i++ {
		b[i] = 0
	}
	x.Encrypt(b, b)

	return bytes, nil
}
