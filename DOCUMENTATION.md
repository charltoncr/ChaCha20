```go
package chacha20 // import "chacha20"
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
func New() *ChaCha20_ctx
```
New allocates a new ChaCha20 context. The caller must use KeySetup and
IvSetup to set up the new context. The default number of rounds is 20.

## func NewWithKeyIv
```go
func NewWithKeyIv(key, iv []byte) (ctx *ChaCha20_ctx)
```
NewWithKeyIv allocates a new ChaCha20 context and for convenience sets up
the new context with the caller's key and iv. The default number of rounds
is 20.

## func 
```go
func (x *ChaCha20_ctx) Decrypt(c, m []byte)
```
Decrypt puts plaintext into m given ciphertext c. Any length is allowed for
c. The same memory may be used for c and m. Decrypt panics if m is not at
least as long as c.

## func 
```go
func (x *ChaCha20_ctx) Encrypt(m, c []byte)
```
Encrypt puts ciphertext into c given plaintext m. Any length is allowed for
m. The same memory may be used for m and c. Encrypt panics if c is not at
least as long as m.

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
Keystream fills stream with bytes from x's keystream.

## func 
```go
func (x *ChaCha20_ctx) SetRounds(r int)
```
SetRounds sets the number of rounds used by Encrypt, Decrypt and Keystream
for a ChaCha20 context. The valid values for r are 8, 12 and 20. SetRounds
ignores any other value. The default number of rounds is 20 for ChaCha20.
Fewer rounds may be less secure. More rounds consume more compute time.
ChaCha8 requires 8, ChaCha12 requires 12 and ChaCha20 requires 20.


