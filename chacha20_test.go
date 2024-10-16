// chacha20_test.go - test ChaCha20 implementation.
// By Ron Charlton, public domain, 2022-08-28.

package chacha20

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"io"
	"log"
	"testing"
)

var _ io.Reader = &ChaCha20_ctx{}
var _ cipher.Stream = &ChaCha20_ctx{}

func TestChaCha20(t *testing.T) {
	// IETF test vector for 20 rounds with a zero key and iv. Key length: 32
	// See https://datatracker.ietf.org/doc/html/draft-strombergson-chacha-test-vectors-00
	want := []byte{
		// block 1
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
		0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
		0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
		0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
		0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
		0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
		0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
		0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
		// block 2
		0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
		0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
		0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
		0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
		0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
		0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
		0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
		0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
	}
	got := make([]byte, 128)
	key := make([]byte, 32)
	iv := make([]byte, 8)
	ctx := New(key, iv)
	ctx.Encrypt(got, got)
	if !bytes.Equal(got, want) {
		t.Errorf("Encrypt(), got %v\nwant %v", got, want)
	}

	// test piecewise encryption
	ctx = New(key, iv)
	out := make([]byte, 8)
	zeros := make([]byte, 8)
	got = []byte{}
	for i := 0; i < len(want); i += 8 {
		ctx.Encrypt(zeros, out)
		got = append(got, out...)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Encrypt() piecewise, got %v\nwant %v", got, want)
	}

	// Keystream should yield same result as Encrypt with input all zeros
	ctx = New(key, iv)
	ctx.Keystream(got)
	if !bytes.Equal(got, want) {
		t.Errorf("Keystream() got %v\nwant %v", got, want)
	}

	// Seek to block 0 should yield same result with Keystream
	ctx.Seek(0)
	ctx.Keystream(got)
	if !bytes.Equal(got, want) {
		t.Errorf("Keystream() after Seek(0) got %v\nwant %v", got, want)
	}

	// test Seek(1) correct endian-ness
	ctx.Seek(1)
	block2 := make([]byte, blockLen)
	ctx.Keystream(block2)
	if !bytes.Equal(block2, want[blockLen:]) {
		t.Errorf("Seek(1), got %v\nwant %v", got, want[blockLen:])
	}

	// Test Read
	ctx.Seek(0)
	n, err := ctx.Read(got)
	if err != nil {
		t.Errorf("Read() err:\ngot %v\nwant %v", err, nil)
	}
	if n != len(want) {
		t.Errorf("Read() return length: got %d\nwant %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Read() after Seek(0) got %v\nwant %v", got, want)
	}

	// Test Read for io.EOF when keystream is exhausted, then panic.
	got = make([]byte, 64)
	ctx.Seek(0xffffffffffffffff)
	n, err = ctx.Read(got)
	if err != io.EOF {
		t.Errorf("Read() got %v want %v", err, io.EOF)
	}
	if n != blockLen {
		t.Errorf("Read() return length at EOF: got %d\nwant %d", n, blockLen)
	}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("ChaCha20 did not panic for Read after EOF")
			}
		}()
		ctx.Read(got[:1])
	}()

	// Seek to block 0 should yield same result with XORKeyStream
	ctx.Seek(0)
	got = make([]byte, 128)
	ctx.XORKeyStream(got, got)
	if !bytes.Equal(got, want) {
		t.Errorf("XORKeyStream() after Seek(0) got %v\nwant %v", got, want)
	}

	// Do a simple encrypt/decrypt and verify they are complementary.
	_, err = crand.Read(key)
	if err != nil {
		log.Fatalf("error from crypto/rand.Read: %v", err)
	}
	_, err = crand.Read(iv)
	if err != nil {
		log.Fatalf("error from crypto/rand.Read: %v", err)
	}

	ctx = New(key, iv)
	m = make([]byte, 50000)
	c := make([]byte, len(m))
	crand.Read(m)
	ctx.Encrypt(m, c)

	// must decrypt with the same key and iv as used to encrypt
	want = m
	ctx.Seek(0)
	got = make([]byte, len(c))
	ctx.Decrypt(c, got)
	if !bytes.Equal(got, want) {
		t.Errorf("simple enc/dec - got[:5]: %v; want[:5]: %v", got[:5], want[:5])
	}
	ctx.Seek(0)
}

// setup for benchmarks:
var m, key, iv []byte
var ctx *ChaCha20_ctx

func init() {
	m = make([]byte, 5000000)
	_, err := crand.Read(m)
	if err != nil {
		log.Fatalf("error from crypto/rand.Read: %v", err)
	}
	key = make([]byte, 32)
	crand.Read(key)
	iv = make([]byte, 8)
	crand.Read(iv)
	ctx = New(key, iv)
}

func BenchmarkChaCha_8rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, m)
	}
}

func BenchmarkChaCha_12rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, m)
	}
}

func BenchmarkChaCha_20rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, m)
	}
}

func BenchmarkChaCha_Read(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Read(m)
	}
}
