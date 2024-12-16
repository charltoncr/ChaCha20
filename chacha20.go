// chacha20.go - public domain ChaCha20 encryption/decryption.
// Public domain is per <https://creativecommons.org/publicdomain/zero/1.0/>
//
// See https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
// for a description of ChaCha20.
//
// I used clang -E to pre-process chacha[-ref].c from
// <https://cr.yp.to/chacha.html> to produce a prototype chacha20.go file,
// then hand- and sed-edited it to make true Go source code.  I added
// New, Seek, XORKeyStream, Read, SetRounds, IvSetupUint64,
// and made the default number of rounds 20.
//
// Much later I parallelized the Encrypt method that all other methods
// depend on.  It resulted in 10X the speed for large input data
// on a 12-processor M2 Max Mac Studio.
//
// From the C file (chacha[-ref].c (at https://cr.yp.to/chacha.html):
//		chacha-ref.c version 20080118
//		D. J. Bernstein
//		Public domain.
//
// This file (chacha20.go):
//		Author:  Ron Charlton <Ron[@]RonCharlton[.]org>
//		Created: 2022-08-28
//		Public domain.
//
// A line of code from chacha-ref.c:  x->input[8] = U8TO32_LITTLE(k + 0);
// This indicates that conversion from byte[] to uint32 is little-endian.
//
// Type byte must be an alias for uint8.
//
// Example use (encrypt a file to another file; not sufficient for
// cryptographic use unless key and iv are set appropriately):
//		// 32-byte key and 8-byte iv assumed.
//		// (error checks omitted)
//		b, err := os.ReadFile("myfile")
//		ctx := chacha20.New(key, iv)
//		ctx.Encrypt(b, b)
//		err = os.WriteFile("myfile.encrypted", b, 0644)
//
// chacha20.go v6.42 Encrypt on 3.504 GHz M2 Max Mac Studio w/12 processors,
// 5 MB message, and 100 blocks-per-chunk parallel processing (go test -bench=.):
//
//	 Rounds	 GB/s  ns/block
//	 ------	 ----  --------
//	    8	 6.45     10
//	   12	 5.34     12
//	   20	 4.01     15
//
//	 Read: 3.6 GB/s.
//
// See an alternate implementation of chacha at
// https://github.com/skeeto/chacha-go.  That implementation is vastly slower
// than this implementation for long length plaintext/ciphertext/keystream.
//
// $Id: chacha20.go,v 6.51 2024-12-16 06:14:09-05 ron Exp $
////

// Package chacha20 provides public domain ChaCha20 encryption and decryption.
// Package chacha20 is derived from public domain chacha[-ref].c at
// <https://cr.yp.to/chacha.html>. It implements io.Reader and
// crypto/cipher.Stream, as well as numerous other methods.
//
// Some chacha20 methods panic when the ChaCha key stream is exhausted
// after producing about 1.2 zettabytes.  A zettabyte is so much data that
// it is nearly impossible to generate that much.  At 1 ns/block it
// would take 584+ years to generate 1.2 zettabytes.
//
// Some chacha20 methods also panic when the method's destination is
// shorter than its source, or when an invalid length key or iv is given,
// or when an invalid number of rounds is specified.
package chacha20

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// change to true to show all debug messages
const debug = false

// change to true to show only n after each of pre-chunk, chunk and
// post-chunk processing
const debugOutline = false

// Rounds can be 8, 12 or 20.  Lower numbers are likely less secure.
// Higher numbers consume more compute time.  ChaCha20 requires 20,
// ChaCha12 requires 12, and ChaCha8 requires 8.
const defaultRounds = 20

// Using individual variables instead of an array provides 32% faster code.
func salsa20_wordtobyte(input []uint32, rounds int, output []byte) {
	var t uint32
	var z int

	a := input[0]
	b := input[1]
	c := input[2]
	d := input[3]
	e := input[4]
	f := input[5]
	g := input[6]
	h := input[7]
	i := input[8]
	j := input[9]
	k := input[10]
	l := input[11]
	m := input[12]
	n := input[13]
	o := input[14]
	p := input[15]

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

// ChaCha block length in bytes
const blockLen int = 64

// ChaCha20_ctx contains state information for a ChaCha20 context.
// ChaCha20_ctx implements the io.Reader and the crypto/cipher.Stream
// interfaces.
type ChaCha20_ctx struct {
	input  [blockLen / 4]uint32
	output [blockLen]byte
	next   int
	eof    bool
	rounds int
}

// New allocates a new ChaCha20 context and sets it up
// with the caller's key and iv.  The default number of rounds is 20.
func New(key, iv []byte) (ctx *ChaCha20_ctx) {
	ctx = &ChaCha20_ctx{
		next:   blockLen,
		rounds: defaultRounds,
	}
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	return
}

// SetRounds sets the number of rounds used by Encrypt, Decrypt, Read,
// XORKeyStream and Keystream for a ChaCha20 context.
// The valid values for r: 8, 12 and 20.
// SetRounds panics with any other value.  ChaCha20's default number
// of rounds is 20.  Smaller r values are likely less secure but are faster.
// ChaCha8 requires 8 rounds, ChaCha12 requires 12 and ChaCha20 requires 20.
func (x *ChaCha20_ctx) SetRounds(r int) {
	if !(r == 8 || r == 12 || r == 20) {
		panic("chacha20:SetRounds: invalid number of rounds")
	}
	x.rounds = r
}

var sigma = []byte("expand 32-byte k")
var tau = []byte("expand 16-byte k")

// KeySetup sets up ChaCha20 context x with key.
// KeySetup panics if len(key) is not 16 or 32. A key length of 32 is
// recommended.
func (x *ChaCha20_ctx) KeySetup(key []byte) {
	var constants []byte
	kbytes := len(key)

	if kbytes != 16 && kbytes != 32 {
		panic("chacha20: invalid key length; must be 16 or 32 bytes.")
	}

	x.input[4] = binary.LittleEndian.Uint32(key[0:])
	x.input[5] = binary.LittleEndian.Uint32(key[4:])
	x.input[6] = binary.LittleEndian.Uint32(key[8:])
	x.input[7] = binary.LittleEndian.Uint32(key[12:])

	if kbytes == 32 {
		key = key[16:]
		constants = sigma
	} else {
		constants = tau
	}

	x.input[8] = binary.LittleEndian.Uint32(key[0:])
	x.input[9] = binary.LittleEndian.Uint32(key[4:])
	x.input[10] = binary.LittleEndian.Uint32(key[8:])
	x.input[11] = binary.LittleEndian.Uint32(key[12:])
	x.input[0] = binary.LittleEndian.Uint32(constants[0:])
	x.input[1] = binary.LittleEndian.Uint32(constants[4:])
	x.input[2] = binary.LittleEndian.Uint32(constants[8:])
	x.input[3] = binary.LittleEndian.Uint32(constants[12:])
}

// IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
// It also calls Seek(0).
// IvSetup panics if len(iv) is not 8.
func (x *ChaCha20_ctx) IvSetup(iv []byte) {
	if len(iv) != 8 {
		panic("chacha20: invalid iv length; must be 8.")
	}
	x.Seek(0)
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
}

// IvSetupUint64 sets x's initialization vector (nonce) to the value in n.
// It also calls Seek(0).
func (x *ChaCha20_ctx) IvSetupUint64(n uint64) {
	var b [8]byte
	x.Seek(0)
	binary.LittleEndian.PutUint64(b[:], n)
	x.input[14] = binary.LittleEndian.Uint32(b[0:])
	x.input[15] = binary.LittleEndian.Uint32(b[4:])
}

// Seek moves x directly to 64-byte block number n in constant time.
// Seek(0) sets x back to its initial state.
func (x *ChaCha20_ctx) Seek(n uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	x.input[12] = binary.LittleEndian.Uint32(b[0:])
	x.input[13] = binary.LittleEndian.Uint32(b[4:])
	x.eof = false
	x.next = blockLen
}

// GetCounter returns x's block counter value.
func (x *ChaCha20_ctx) GetCounter() (n uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:], x.input[12])
	binary.LittleEndian.PutUint32(b[4:], x.input[13])
	return binary.LittleEndian.Uint64(b[:])
}

// Encrypt puts ciphertext into c given plaintext m.  Any length is allowed
// for m.  Parameters m and c must overlap completely or not at all.
// Encrypt panics if len(c) is less than len(m).  len(c) can be larger than
// len(m).  The message to be encrypted can be processed
// in sequential segments with multiple calls to Encrypt.
//
// Encrypt returns io.EOF when the key stream is exhausted
// after producing 1.2 zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless x has been
// re-initialized.
// The same key and iv values used to encrypt a message must be used to
// decrypt the message.  Messages/Reads over about 6,400 bytes long will
// be processed in parallel for 2 to 10 times faster processing.
func (x *ChaCha20_ctx) Encrypt(m, c []byte) (n int, err error) {
	size := len(m)
	if size == 0 {
		return
	}
	if len(c) < size {
		panic("chacha20.Encrypt: insufficient space; c is shorter than m.")
	}
	idx := x.next
	if x.eof && idx >= blockLen {
		panic("chacha20: key stream is exhausted")
	}

	// ====== Process any x.next values left over from earlier Encrypt
	// calls by aligning n with 64-byte blocks (idx == blockLen). ======
	for ; n < size && idx < blockLen; n++ {
		if idx >= blockLen {
			if x.eof {
				break
			}
			salsa20_wordtobyte(x.input[:], x.rounds, x.output[:])
			x.input[12]++
			if x.input[12] == 0 {
				x.input[13]++
				if x.input[13] == 0 {
					x.eof = true
				}
			}
			idx = 0
		}
		c[n] = m[n] ^ x.output[idx]
		idx++
	}
	if debug || debugOutline {
		fmt.Printf("\nfinished pre-chunk processing; n=%d\n", n)
	}
	x.next = idx
	if x.eof && idx >= blockLen {
		err = io.EOF
		return
	}

	// ==== Chunk-process with goroutines if possible. One chunk per goroutine.
	// Messages longer than about 6,400 bytes will be chunk-processed
	// unless x.eof==true would occur during chunking. ====
	// idx==blockLen must be true here.
	const blocksPerChunk = 100 // empirically determined on 3.5 GHz Mac M2 Max
	const chunkLen = blockLen * blocksPerChunk
	if size-n > chunkLen {
		wg := sync.WaitGroup{}
		baseBlock := x.GetCounter()
		chunkCount := uint64((size - n) / chunkLen) // how many chunks to proc.
		if baseBlock+chunkCount*blocksPerChunk > baseBlock {
			// keystream exhaustion (io.EOF) won't occur during chunk processing
			for chunk := uint64(0); chunk < chunkCount; chunk++ {
				wg.Add(1)
				go func(r ChaCha20_ctx, blk uint64, ni int) {
					defer wg.Done()
					r.Seek(blk)
					for j := 0; j < blocksPerChunk; j++ {
						salsa20_wordtobyte(r.input[:], r.rounds, r.output[:])
						r.input[12]++
						if r.input[12] == 0 {
							r.input[13]++
						}
						for i := 0; i < blockLen; i++ {
							c[ni] = m[ni] ^ r.output[i]
							ni++
						}
					}
				}(*x, baseBlock, n)
				baseBlock += blocksPerChunk
				n += chunkLen
			}
			wg.Wait()
			if debug {
				fmt.Printf("baseBlock=%d  chunkCount=%d  n=%d\n",
					baseBlock, chunkCount, n)
			}
			x.Seek(baseBlock)
			x.next = blockLen
			idx = blockLen
		}
	}
	if debug || debugOutline {
		fmt.Printf("finished chunk processing; n=%d\n", n)
	}

	// ======= process all bytes left over after chunk processing  =======
	for ; n < size; n++ {
		if idx >= blockLen {
			if x.eof {
				break
			}
			salsa20_wordtobyte(x.input[:], x.rounds, x.output[:])
			x.input[12]++
			if x.input[12] == 0 {
				x.input[13]++
				if x.input[13] == 0 {
					x.eof = true
				}
			}
			idx = 0
		}
		c[n] = m[n] ^ x.output[idx]
		idx++
	}
	x.next = idx

	if debug || debugOutline {
		fmt.Printf("finished post-chunk processing; n=%d\n", n)
	}
	if x.eof && idx >= blockLen {
		err = io.EOF
	}
	return
}

// Decrypt puts plaintext into m given ciphertext c.  Any length is allowed
// for c.  Parameters m and c must overlap completely or not at all.
// Decrypt panics if len(m) is less than len(c).  len(m) can be larger than
// len(c).  The message to be decrypted can be processed in
// sequential segments with multiple calls to Decrypt.
//
// Decrypt returns io.EOF when the key stream is exhausted
// after producing 1.2 zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless x has been
// re-initialized.
// The same key and iv used to encrypt a message must be used to decrypt
// the message.
func (x *ChaCha20_ctx) Decrypt(c, m []byte) (int, error) {
	if x.eof {
		panic("chacha20.Decrypt: key stream is exhausted")
	}
	if len(m) < len(c) {
		panic("chacha20.Decrypt: insufficient space; m is shorter than c.")
	}
	return x.Encrypt(c, m)
}

// Keystream fills stream with cryptographically secure pseudorandom bytes
// from x's key stream when a random key and iv are used.  Keystream
// panics when the ChaCha key stream is exhausted after producing 1.2 zettabytes.
func (x *ChaCha20_ctx) Keystream(stream []byte) {
	if x.eof {
		panic("chacha20.Keystream: key stream is exhausted")
	}
	t := make([]byte, len(stream)) // 3X faster than zeroing stream first
	x.Encrypt(t, stream)
}

// The idea for adding XORKeyStream and Read came from skeeto's public
// domain ChaCha-go implementation.  Neither is copied or ported from that
// implementation.

// XORKeyStream implements the crypto/cipher.Stream interface.
// XORKeyStream XORs src bytes with ChaCha's key stream and puts the result
// in dst.  XORKeyStream panics if len(dst) is less than len(src), or
// when the ChaCha key stream is exhausted after producing 1.2 zettabytes.
func (x *ChaCha20_ctx) XORKeyStream(dst, src []byte) {
	if x.eof && len(src) >= blockLen {
		panic("chacha20.XORKeyStream: key stream is exhausted")
	}
	if len(dst) < len(src) {
		panic("chacha20.XORKeyStream: insufficient space; dst is shorter than src.")
	}
	x.Encrypt(src, dst)
}

// Read fills b with cryptographically secure pseudorandom bytes from x's
// key stream when a random key and iv are used.
// Read implements the io.Reader interface.
// Read returns io.EOF when the key stream is exhausted after producing 1.2
// zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless x is re-initialized.
func (x *ChaCha20_ctx) Read(b []byte) (int, error) {
	if x.eof {
		panic("chacha20.Read: key stream is exhausted")
	}
	t := make([]byte, len(b)) // 3X faster than zeroing b first
	return x.Encrypt(t, b)
}
