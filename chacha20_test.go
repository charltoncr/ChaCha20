// chacha20_test.go - test chacha20 implementation.
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
	// First do a simple encrypt/decrypt and verify they are complementary.
	key := make([]byte, 256)
	crand.Read(key)
	iv := make([]byte, 8)
	crand.Read(iv)

	ctx := New()
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	m := make([]byte, 50000)
	crand.Read(m)
	c := make([]byte, len(m))
	ctx.Encrypt(m, c)
	if bytes.Compare(m, c) == 0 {
		t.Errorf("m: %v; c: %v", m[:5], c[:5])
	}

	// must decrypt with the same key and iv as used to encrypt
	want := m
	ctx.KeySetup(key)
	ctx.IvSetup(iv)
	got := make([]byte, len(c))
	ctx.Decrypt(c, got)
	if bytes.Compare(want, got) != 0 {
		t.Errorf("want: %s; got: %s", want[:5], got[:5])
	}

	// Compare encryption by chacha20.go with that of chacha-ref.c from
	// <https://cr.yp.to/chacha.html>.  chacha-ref.c's rounds must be set to 20
	// to match chacha20.go's default number of rounds.
	// Key and iv files were made with 'genfile -r'.  publicDomainEncrypted.dat
	// was created from publicDomain.txt with chacha20encrypt.c that calls
	// chacha-ref.c code with rounds set to 20.
	var err error
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

	ctx = NewWithKeyIv(key, iv)
	got = make([]byte, len(m))
	ctx.Encrypt(m, got)
	if len(got) != len(want) {
		t.Errorf("Encrypt: len(want): %d; len(got): %d", len(want), len(got))
	}
	if bytes.Compare(want, got) != 0 {
		t.Errorf("Encrypt: want: %v; got: %v", want[:5], got[:5])
	}

	// must decrypt with the same key and iv as used to encrypt
	ctx = NewWithKeyIv(key, iv)
	ctx.Decrypt(want, got)
	if len(got) != len(m) {
		t.Errorf("Decrypt: len(m): %d; len(got): %d", len(m), len(got))
	}
	if bytes.Compare(m, got) != 0 {
		t.Errorf("Decrypt: want: %v; got: %v", m[:5], got[:5])
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
	key = make([]byte, 256)
	crand.Read(key)
	iv = make([]byte, 8)
	crand.Read(iv)
	ctx = NewWithKeyIv(key, iv)
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
