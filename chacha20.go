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
// memory, goroutines are throttled at 300 simultaneous instances.
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
// cryptographic use unless key and iv are set appropriately, etc.):
//		// 32-byte key and 8-byte iv assumed.
//		// (error checks omitted)
//		b, err := os.ReadFile("myfile")
//		ctx := chacha20.New(key, iv)
//		ctx.Encrypt(b, b)
//		err = os.WriteFile("myfile.encrypted", b, 0644)
//
// chacha20.go v6.80 Encrypt on 3.504 GHz M2 Max Mac Studio w/12 processors,
// 5 MB message, and 200 blocks-per-chunk parallel processing (go test -bench=.):
//
//	 Rounds	 GB/s  ns/block
//	 ------	 ----  --------
//	    8	 6.3      10      Default Tuning [=TuneParallel(200, 300)]
//	   12	 5.2      12            "
//	   20	 3.8      16            "
//     20    0.46    140      NewSmallMemory
//      8    6.5       9.6    TuneParallel(400, 3000) (~maximum speed)
//     20    2.1      30      TuneParallel(50, 30)    (~minimun memory)
//
//	 Read:
//     Rounds   GB/s
//     ------   ----
//		 8      5.0
//		12      4.3
//		20      3.6
//
// See an alternate implementation of chacha at
// https://github.com/skeeto/chacha-go.  That implementation is vastly slower
// than this implementation for long length plaintext/ciphertext/keystream/Read.
//
// $Id: chacha20.go,v 6.82 2025-08-04 07:03:37-04 ron Exp $
////

// Package chacha20 provides public domain ChaCha20 encryption and decryption.
// It is derived from public domain file chacha[-ref].c at
// <https://cr.yp.to/chacha.html>. It implements the io.Reader and
// crypto/cipher.Stream interfaces, as well as several other methods.
//
// On long byte slices (>25,600 bytes) ChaCha20 provides speed approximating
// that of hardware-implemented AES encryption.
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
// Parallel processing can allocate up to 11,200 bytes of memory. If memory
// is tight
// call NewSmallMemory() instead of New for a much smaller memory footprint.
// Processing speed then will be dramatically slower for long byte slices.
// As an alternative, TuneParallel can also adjust memory allocation vs speed
// for parallel processing, achieving four times the speed of non-parallel
// processing with a minimal memory footprint.
package chacha20

import (
	"encoding/binary"
	"io"
	"sync"
)

// Rounds can be 8, 12 or 20.  Lower numbers are likely less secure.
// Higher numbers consume more compute time.  ChaCha20 requires 20,
// ChaCha12 requires 12, and ChaCha8 requires 8 rounds.
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
const blockLen = 64

// Tuneable parameters; can be set programmatically via TuneParallel.

// Limit memory allocation to 51.6 KB by limiting the number of simultaneous
// goroutines.  Larger maxRoutines values have little effect on speed.
// Each simultaneous goroutine adds about 172 B of simultaneous memory allocation.
// Empirically determined on 12 processor 3.504 GHz Apple Studio with M2 Max.
// The effective number can be changed with TuneParallel.  This is the
// default value.
const maxGoroutines = 300

// blocksPerChunk is used in parallel processing; it can be changed with
// TuneParallel. It determines the number of blocks processed by each
// goroutine and thus determines the minimum size of message that will be
// parallel-processed.
const blocksPerChunk = 200 // empirically determined on 3.5 GHz Mac M2 Max

// End tuneable parameters

// Ctx contains state information for a ChaCha20 context.
// Ctx implements the io.Reader and the crypto/cipher.Stream
// interfaces.
type Ctx struct {
	input          [blockLen / 4]uint32
	output         [blockLen]byte
	next           int
	eof            bool
	rounds         int
	parallel       bool
	blocksPerChunk int
	goroutinesMax  int
	guard          chan struct{}
}

// New allocates a new ChaCha20 context and sets it up
// with the caller's key and iv.  The default number of rounds is 20.  To
// use a different number of rounds, call SetRounds also.
func New(key, iv []byte) (ctx *Ctx) {
	ctx = &Ctx{
		next:           blockLen,
		rounds:         defaultRounds,
		parallel:       true,
		blocksPerChunk: blocksPerChunk,
		goroutinesMax:  maxGoroutines,
		guard:          make(chan struct{}, maxGoroutines),
	}
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	return
}

// NewSmallMemory allocates a context the same as New does but doesn't use
// parallel processing.  Processing speed will be dramtically slower and memory
// use will be much less for long messages.  The default number of rounds is 20.
// To use a different number of rounds, call SetRounds also.
func NewSmallMemory(key, iv []byte) (ctx *Ctx) {
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
func (x *Ctx) SetRounds(r int) {
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
func (x *Ctx) KeySetup(key []byte) {
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
func (x *Ctx) IvSetup(iv []byte) {
	if len(iv) != 8 {
		panic("chacha20: invalid iv length; must be 8.")
	}
	x.Seek(0)
	x.input[14] = binary.LittleEndian.Uint32(iv[0:])
	x.input[15] = binary.LittleEndian.Uint32(iv[4:])
}

// IvSetupUint64 sets x's initialization vector (nonce) to the value in n.
// It also calls Seek(0).
func (x *Ctx) IvSetupUint64(n uint64) {
	var b [8]byte
	x.Seek(0)
	binary.LittleEndian.PutUint64(b[:], n)
	x.input[14] = binary.LittleEndian.Uint32(b[0:])
	x.input[15] = binary.LittleEndian.Uint32(b[4:])
}

// Seek moves x directly to 64-byte block number n in constant time.
// Seek(0) sets x back to its initial state.
func (x *Ctx) Seek(n uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	x.input[12] = binary.LittleEndian.Uint32(b[0:])
	x.input[13] = binary.LittleEndian.Uint32(b[4:])
	x.eof = false
	x.next = blockLen
}

// GetCounter returns x's block counter value.
func (x *Ctx) GetCounter() (n uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:], x.input[12])
	binary.LittleEndian.PutUint32(b[4:], x.input[13])
	return binary.LittleEndian.Uint64(b[:])
}

// UseParallel accepts a boolean to determine whether x uses parallel
// processing.  Parallel operation uses larger amounts of memory; if
// memory is scarce call UseParallel with b false after calling New.
// False b will result in dramatically slower speed for all ChaCha20 operations.
// Calling UseParallel is not necessary if NewSmallMemory was used to
// instantiate x.
func (x *Ctx) UseParallel(b bool) {
	x.parallel = b
}

// TuneParallel is not required for typical ChaCha20 use.  In unusual
// circumstances it allows adjustments to parallel processing parameters
// to make time and space tradeoffs.  Each Ctx instance has its own
// parallel processing parameters.
// Defaults are equivalent to TuneParallel(200, 300).
//
// TuneParallel has no effect on processing short messages, or when parallel
// processing is disabled by calling UseParallel(false) or NewSmallMemory.
//
// If BlocksPerGoroutine > 0 it sets how many ChaCha20 blocks of
// 64 bytes are processed by each goroutine instance.  Smaller values slow
// processing generally, but allow shorter length messages to be processed
// in parallel, thereby speeding up processing for them.
//
// If MaxGoroutines > 0 it determines how many goroutines can run
// simultaneously.
// Larger values will speed up processing, also allowing more memory
// to be allocated at once. The default value, 300, results in simultaneous
// allocation of 51,600 bytes.  Maximum simultaneous memory allocation is
// MaxGoroutines * 172.  Go documentation recommends
// liberty when issuing simultaneous goroutines, stating that 3,000
// goroutines are easily managed by the Go runtime.
//
// To change only one parameter in a call use zero for other parameter.
//
// With TuneParallel(50, 300) (allowing parallel processing of messages as
// short as 6,400 bytes) ChaCha20 with parallel processing is 4.6 times as
// fast (2.1 GB/s vs 457 MB/s) as non-parallel processing on a
// 3.5 GHz Apple M2 with 12 processors.  YMMV.
func (x *Ctx) TuneParallel(BlocksPerGoroutine, MaxGoroutines int) {
	if BlocksPerGoroutine > 0 {
		x.blocksPerChunk = BlocksPerGoroutine
	}

	if MaxGoroutines > 0 {
		x.guard = make(chan struct{}, MaxGoroutines)
	}
}

// Encrypt puts ciphertext into c given plaintext m.  Any length is allowed
// for m.  Parameters m and c must overlap completely or not at all.
// Encrypt panics if len(c) < len(m).  len(c) can be greater than
// len(m).  The message to be encrypted can be processed
// in sequential segments with multiple calls to Encrypt.
//
// Encrypt returns io.EOF when the key stream is exhausted
// (extremely improbable) after producing 1.2 zettabytes.
// It will panic if called with the the same x after io.EOF is returned,
// unless x has been re-initialized.
//
// The same key, iv and rounds used to encrypt a message must be used to
// decrypt the message.  Messages and Reads over about 25,600 bytes long will
// be parallel processed 2-10 times as fast, unless NewSmallMemory is
// used to allocate x.
func (x *Ctx) Encrypt(m, c []byte) (n int, err error) {
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
		var blocksPerChunk = x.blocksPerChunk
		var chunkLen = blockLen * blocksPerChunk
		if size-n > chunkLen*2 {
			baseBlock := x.GetCounter()
			chunkCount := uint64((size - n) / chunkLen) // how many chunks to process
			if baseBlock+chunkCount*uint64(x.blocksPerChunk) > baseBlock {
				// chunk processing won't reach keystream exhaustion (io.EOF)
				wg := sync.WaitGroup{}
				for chunk := uint64(0); chunk < chunkCount; chunk++ {
					x.guard <- struct{}{} // blocks to limit simultaneous goroutines
					wg.Add(1)
					go func(r Ctx, blk uint64, ni int) {
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
						<-x.guard
					}(*x, baseBlock, n)
					baseBlock += uint64(blocksPerChunk)
					n += chunkLen
				}
				wg.Wait()
				x.Seek(baseBlock)
				x.next = blockLen
				idx = blockLen
			}
		}

	} // if x.parallel

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
func (x *Ctx) Decrypt(c, m []byte) (int, error) {
	if x.eof && x.next >= blockLen {
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
func (x *Ctx) Keystream(stream []byte) {
	if x.eof && len(stream) >= blockLen {
		panic("chacha20.Keystream: key stream is exhausted")
	}
	t := make([]byte, len(stream)) // 3X faster than zeroing stream first
	x.Encrypt(t, stream)
}

// The idea for adding XORKeyStream and Read came from skeeto's public
// domain ChaCha-go implementation.  Neither is copied nor ported from that
// implementation.

// XORKeyStream implements the crypto/cipher.Stream interface.
// XORKeyStream XORs src bytes with ChaCha's key stream and puts the result
// in dst.  XORKeyStream panics if len(dst) is less than len(src), or
// when the ChaCha key stream is exhausted after producing 1.2 zettabytes.
func (x *Ctx) XORKeyStream(dst, src []byte) {
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
func (x *Ctx) Read(b []byte) (int, error) {
	if x.eof && len(b) >= blockLen {
		panic("chacha20.Read: key stream is exhausted")
	}
	t := make([]byte, len(b)) // 3X faster than zeroing b first
	return x.Encrypt(t, b)
}
