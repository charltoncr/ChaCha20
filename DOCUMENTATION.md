```go
package chacha20 // import "chacha20"
```
```go
Package chacha20 provides public domain ChaCha20 encryption and decryption.
Package chacha20 is derived from public domain chacha-ref.c at
<https://cr.yp.to/chacha.html>.
```
## TYPES

ChaCha20_ctx contains state information for a ChaCha20 context.
```go
type ChaCha20_ctx struct {
	// Has unexported fields.
}
```
## func New
```go
func New(key, iv []byte) (ctx *ChaCha20_ctx)
```
New allocates a new ChaCha20 context and sets it up with the caller's key
and iv. The default number of rounds is 20.

## func 
```go
func (x *ChaCha20_ctx) Decrypt(c, m []byte)
```
Decrypt puts plaintext into m given ciphertext c. Any length is allowed
for c. The same memory may be used for c and m. Decrypt panics if len(m)
is less than len(c) or when the keystream is exhausted after producing 1.2
zettabytes.

## func 
```go
func (x *ChaCha20_ctx) Encrypt(m, c []byte)
```
Encrypt puts ciphertext into c given plaintext m. Any length is allowed
for m. The same memory may be used for m and c. Encrypt panics if len(c)
is less than len(m) or when the keystream is exhausted after producing 1.2
zettabytes.

## func 
```go
func (x *ChaCha20_ctx) IvSetup(iv []byte)
```
IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
It also sets the context's counter to 0. IvSetup panics if len(iv) is not 8.

## func 
```go
func (x *ChaCha20_ctx) KeySetup(k []byte)
```
KeySetup sets up ChaCha20 context x with key k. KeySetup panics if len(k) is
not 16 or 32. A key length of 32 is recommended.

## func 
```go
func (x *ChaCha20_ctx) Keystream(stream []byte)
```
Keystream fills stream with bytes from x's keystream. Keystream panics when
the ChaCha keystream is exhausted after producing 1.2 zettabytes.

## func 
```go
func (x *ChaCha20_ctx) Read(b []byte) (int, error)
```
Read fills b with bytes from x's keystream. Read always returns len(b) and
a nil error. Read implements the io.Reader interface. Read panics when the
keystream is exhausted after producing 1.2 zettabytes.

## func 
```go
func (x *ChaCha20_ctx) Seek(n uint64)
```
Seek moves x directly to 64-byte block number n in constant time.

## func 
```go
func (x *ChaCha20_ctx) SetRounds(r int)
```
SetRounds sets the number of rounds used by Encrypt, Decrypt, Read and
Keystream for a ChaCha20 context. The valid values for r are 8, 12 and 20.
SetRounds ignores any other value. ChaCha20's default number of rounds is
20. Fewer rounds may be less secure. More rounds consume more compute time.
ChaCha8 requires 8 rounds, ChaCha12 requires 12 and ChaCha20 requires 20.


