// chacha20_test.go - test ChaCha20 implementation.
// By Ron Charlton, public domain, 2022-08-28.

package chacha20

import (
	"bytes"
	crand "crypto/rand"
	"log"
	"os"
	"testing"
)

func TestChaCha20(t *testing.T) {
	// Official IETF test vectors for 20 rounds on a zero key and IV
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
	if bytes.Compare(got, want) != 0 {
		t.Errorf("chacha20.Encrypt(), got %v\nwant %v", got, want)
	}

	// test piecewise encryption
	ctx = New(key, iv)
	op := make([]byte, 8)
	zeros := make([]byte, 8)
	got = []byte{}
	for i := 0; i < len(want); i += 8 {
		ctx.Encrypt(zeros, op)
		got = append(got, op...)
	}
	if bytes.Compare(got, want) != 0 {
		t.Errorf("chacha20.Encrypt() piecewise, got %v\nwant %v", got, want)
	}

	// Do a simple encrypt/decrypt and verify they are complementary.
	_, err := crand.Read(key)
	if err != nil {
		log.Fatalf("error from crypto/rand.Read: %v", err)
	}
	crand.Read(iv)

	ctx = New(key, iv)
	m := make([]byte, 50000)
	crand.Read(m)
	c := make([]byte, len(m))
	ctx.Encrypt(m, c)
	if bytes.Compare(m, c) == 0 {
		t.Errorf("m: %v; c: %v", m[:5], c[:5])
	}

	// must decrypt with the same key and iv as used to encrypt
	want = m
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	got = make([]byte, len(c))
	ctx.Decrypt(c, got)
	if bytes.Compare(want, got) != 0 {
		t.Errorf("got: %s; want: %s", got[:5], want[:5])
	}

	// Compare encryption by chacha20.go with that of chacha-ref.c from
	// <https://cr.yp.to/chacha.html>.  chacha-ref.c's rounds must be set to 20
	// to match chacha20.go's default number of rounds.
	// Key and iv files were made with 'genfile -r'.  publicDomainEncrypted.dat
	// was created from publicDomain.txt with chacha20encrypt.c that calls
	// chacha-ref.c code with rounds set to 20.
	if key, err = os.ReadFile("publicDomainKey.dat"); err == nil {
		if iv, err = os.ReadFile("publicDomainIv.dat"); err == nil {
			if m, err = os.ReadFile("publicDomain.txt"); err == nil {
				want, err = os.ReadFile("publicDomainEncrypted.dat")
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}

	ctx = New(key, iv)
	got = make([]byte, len(m))
	ctx.Encrypt(m, got)
	if len(got) != len(want) {
		t.Errorf("Encrypt: len(got): %d; len(want): %d", len(got), len(want))
	}
	if bytes.Compare(want, got) != 0 {
		t.Errorf("Encrypt: got: %v; want: %v", got[:5], want[:5])
	}

	c = want
	want = m
	// must decrypt with the same key and iv as used to encrypt
	ctx = New(key, iv)
	ctx.Decrypt(c, got)
	if len(got) != len(want) {
		t.Errorf("Decrypt: len(got): %d; len(want): %d", len(got), len(want))
	}
	if bytes.Compare(want, got) != 0 {
		t.Errorf("Decrypt: got: %v; want: %v", got[:5], m[:5])
	}
}

// setup for benchmarks:
var m, c, key, iv []byte
var ctx *ChaCha20_ctx

func init() {
	m = make([]byte, 5000000)
	_, err := crand.Read(m)
	if err != nil {
		log.Fatalf("error from crypto/rand.Read: %v", err)
	}
	c = make([]byte, len(m))
	key = make([]byte, 32)
	crand.Read(key)
	iv = make([]byte, 8)
	crand.Read(iv)
	ctx = New(key, iv)
}

func BenchmarkChaCha20_8rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, c)
	}
}

func BenchmarkChaCha20_12rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(12)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, c)
	}
}

func BenchmarkChaCha20_20rnds(b *testing.B) {
	b.SetBytes(int64(len(m)))
	ctx.SetRounds(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx.Encrypt(m, c)
	}
}
