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
// Much later I parallelized the Encrypt method that all other relevant
// methods depend on.  It resulted in 8X the speed for large input data
// on a 12-processor M2 Max Mac Studio.  To limit the amount of allocated
// memory goroutines are throttled at 70 simultaneous instances.
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
// chacha20.go v6.71 Encrypt on 3.504 GHz M2 Max Mac Studio w/12 processors,
// 5 MB message, and 100 blocks-per-chunk parallel processing (go test -bench=.):
//
//	 Rounds	 GB/s  ns/block
//	 ------	 ----  --------
//	    8	 5.96     10
//	   12	 4.92     13
//	   20	 3.66     17
//
//	 Read: 3.2 GB/s.
//
// See an alternate implementation of chacha at
// https://github.com/skeeto/chacha-go.  That implementation is vastly slower
// than this implementation for long length plaintext/ciphertext/keystream.
//
// $Id: chacha20.go,v 6.72 2025-03-02 10:33:28-05 ron Exp $
////

// Package chacha20 provides public domain ChaCha20 encryption and decryption.
// It is derived from public domain chacha[-ref].c at
// <https://cr.yp.to/chacha.html>. It implements io.Reader and
// crypto/cipher.Stream, as well as several other methods.
//
// Some chacha20 methods panic when a ChaCha key stream is exhausted
// after producing about 1.2 zettabytes if io.EOF is not honored.
// A zettabyte is so much data that it is nearly impossible to generate
// that much.  At 1 ns/block it would take 584+ years to generate 1.2 zettabytes.
//
// Some chacha20 methods also panic when the method's destination is
// shorter than its source, or when an invalid length key or iv is given,
// or when an invalid number of rounds is specified.
//
// The Encrypt method processes slices over about 25,600 bytes long with
// parallel processing at between 2 and 9 times the speed of mono-processing.
// All chacha20 methods share Encrypt's increased speed on similarly long slices.
//
// Parallel processing can allocate up to 580 KB of memory. If memory is tight
// call NewSmallMemory() instead of New for a much smaller memory footprint.
// Processing speed then will be dramatically slower for long byte slices.
package chacha20

import (
	"encoding/binary"
	"io"
	"sync"
)

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

// Limit memory use to 580 KB by limiting number of simultaneous goroutines.
// Larger maxRoutines value has little effect on speed.
// Empirically determined on 12 processor 3.504 GHz Apple M2 Max.
const maxGoroutines = 70

var guard = make(chan struct{}, maxGoroutines)

// ChaCha block length in bytes
const blockLen int = 64

// ChaCha20_ctx contains state information for a ChaCha20 context.
// ChaCha20_ctx implements the io.Reader and the crypto/cipher.Stream
// interfaces.
type ChaCha20_ctx struct {
	input    [blockLen / 4]uint32
	output   [blockLen]byte
	next     int
	eof      bool
	rounds   int
	parallel bool
}

// New allocates a new ChaCha20 context and sets it up
// with the caller's key and iv.  The default number of rounds is 20.  To
// use a different number of rounds, call SetRounds also.
func New(key, iv []byte) (ctx *ChaCha20_ctx) {
	ctx = &ChaCha20_ctx{
		next:     blockLen,
		rounds:   defaultRounds,
		parallel: true,
	}
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	return
}

// NewSmallMemory allocates a context the same as New does but doesn't use
// parallel processing.  Processing speed will be dramtically slower and memory
// use will be much less for long messages.  The default number of rounds is 20.
// To use a different number of rounds, call ctx.SetRounds also.
func NewSmallMemory(key, iv []byte) (ctx *ChaCha20_ctx) {
	ctx = New(key, iv)
	ctx.parallel = false
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

// UseParallel accepts a boolean to determine whether x uses parallel
// processing.  Parallel operation uses large amounts of memory; if
// memory is scarce call UseParallel with b false after calling New.
// False b will result in dramatically slower speed for all ChaCha20 operations.
// Calling UseParallel is not required if NewSmallMemory was used to
// instantiate x.
func (x *ChaCha20_ctx) UseParallel(b bool) {
	x.parallel = b
}

// Encrypt puts ciphertext into c given plaintext m.  Any length is allowed
// for m.  Parameters m and c must overlap completely or not at all.
// Encrypt panics if len(c) < len(m).  len(c) can be greater than
// len(m).  The message to be encrypted can be processed
// in sequential segments with multiple calls to Encrypt.
//
// Encrypt returns io.EOF when the key stream is exhausted
// after producing 1.2 zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless x has been
// re-initialized.
//
// The same key, iv and rounds used to encrypt a message must be used to
// decrypt the message.  Messages and Reads over about 12,800 bytes long will
// be parallel processed 2-10 times as fast, unless NewSmallMemory is
// used to allocate x.
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

	if x.parallel {

		// ====== Process any x.next values left over from earlier Encrypt
		// calls to align n with 64-byte blocks (idx == blockLen).
		// It prepares for chunk processing. ======
		for ; idx < blockLen && n < size; n++ {
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
		if x.eof && idx >= blockLen {
			err = io.EOF
			return
		}

		// ==== Chunk-process with goroutines if possible. One chunk per goroutine.
		// Messages longer than about 25,600 bytes will be chunk-processed unless
		// x.eof==true (extremely improbable) would occur during chunking. ====
		// idx==blockLen must be true here.
		const blocksPerChunk = 200 // empirically determined on 3.5 GHz Mac M2 Max
		const chunkLen = blockLen * blocksPerChunk
		if size-n > chunkLen*2 {
			baseBlock := x.GetCounter()
			chunkCount := uint64((size - n) / chunkLen) // how many chunks to process
			if baseBlock+chunkCount*blocksPerChunk > baseBlock {
				// chunk processing won't reach keystream exhaustion (io.EOF)
				wg := sync.WaitGroup{}
				for chunk := uint64(0); chunk < chunkCount; chunk++ {
					wg.Add(1)
					guard <- struct{}{} // blocks if guard channel is full
					go func(r ChaCha20_ctx, blk uint64, ni int) {
						defer wg.Done()
						r.Seek(blk)
						for j := 0; j < blocksPerChunk; j++ {
							salsa20_wordtobyte(r.input[:], r.rounds, r.output[:])
							r.input[12]++
							if r.input[12] == 0 {
								r.input[13]++
							}
							for i := range blockLen {
								c[ni] = m[ni] ^ r.output[i]
								ni++
							}
						}
						<-guard
					}(*x, baseBlock, n)
					baseBlock += blocksPerChunk
					n += chunkLen
				}
				wg.Wait()
				x.Seek(baseBlock)
				x.next = blockLen
				idx = blockLen
			}
		}

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

	if x.eof && idx >= blockLen {
		err = io.EOF
	}
	return
}

// Decrypt puts plaintext into m given ciphertext c.  Any length is allowed
// for c.  Parameters m and c must overlap completely or not at all.
// Decrypt panics if len(m) < len(c).  len(m) can be larger than
// len(c).  The message to be decrypted can be processed in
// sequential segments with multiple calls to Decrypt.
//
// Decrypt returns io.EOF when the key stream is exhausted
// after producing 1.2 zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless x has been
// re-initialized.
// The same key, iv and rounds used to encrypt a message must be used
// to decrypt the message.
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
	if x.eof && len(stream) >= blockLen {
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
// key stream when a random key and iv are used with x.
// Read implements the io.Reader interface.
// Read returns io.EOF when the key stream is exhausted after producing 1.2
// zettabytes.  It will panic if called with the
// the same x after io.EOF is returned, unless IvSetup is called with a new
// value first.
func (x *ChaCha20_ctx) Read(b []byte) (int, error) {
	if x.eof && len(b) >= blockLen {
		panic("chacha20.Read: key stream is exhausted")
	}
	t := make([]byte, len(b)) // 3X faster than zeroing b first
	return x.Encrypt(t, b)
}
