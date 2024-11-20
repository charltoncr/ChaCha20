```go
package chacha20 // import "chacha20"
```
```go
Package chacha20 provides public domain ChaCha20 encryption and decryption.
Package chacha20 is derived from public domain chacha[-ref].c
at <https://cr.yp.to/chacha.html>. It implements io.Reader and
crypto/cipher.Stream, as well as numerous other methods.
```
```go
Some chacha20 methods panic when the ChaCha key stream is exhausted after
producing about 1.2 zettabytes. A zettabyte is so much data that it is nearly
impossible to generate that much. At 1 ns/block it would take 584+ years to
generate 1.2 zettabytes.
```
```go
Some chacha20 methods also panic when the method's destination is shorter than
its source, or when an invalid length key or iv is given, or when an invalid
number of rounds is specified.
```
## TYPES

ChaCha20_ctx contains state information for a ChaCha20 context. ChaCha20_ctx
implements the io.Reader and the crypto/cipher.Stream interfaces.
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
func (x *ChaCha20_ctx) Decrypt(c, m []byte) (int, error)
```
Decrypt puts plaintext into m given ciphertext c. Any length is allowed for
c. Parameters m and c must overlap completely or not at all. Decrypt panics
if len(m) is less than len(c). len(m) can be larger than len(c). The message
to be decrypted can be processed in sequential segments with multiple calls
to Decrypt.

Decrypt returns io.EOF when the key stream is exhausted after producing
1.2 zettabytes. It will panic if called with the the same x after io.EOF
is returned, unless x has been re-initialized. The same key and iv used to
encrypt a message must be used to decrypt the message.

## func 
```go
func (x *ChaCha20_ctx) Encrypt(m, c []byte) (n int, err error)
```
Encrypt puts ciphertext into c given plaintext m. Any length is allowed for
m. Parameters m and c must overlap completely or not at all. Encrypt panics
if len(c) is less than len(m). len(c) can be larger than len(m). The message
to be encrypted can be processed in sequential segments with multiple calls
to Encrypt.

Encrypt returns io.EOF when the key stream is exhausted after producing
1.2 zettabytes. It will panic if called with the the same x after io.EOF is
returned, unless x has been re-initialized. The same key and iv values used
to encrypt a message must be used to decrypt the message.

## func 
```go
func (x *ChaCha20_ctx) IvSetup(iv []byte)
```
IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
It also does the equivalent of Seek(0). IvSetup panics if len(iv) is not 8.

## func 
```go
func (x *ChaCha20_ctx) KeySetup(key []byte)
```
KeySetup sets up ChaCha20 context x with key. KeySetup panics if len(key) is
not 16 or 32. A key length of 32 is recommended.

## func 
```go
func (x *ChaCha20_ctx) Keystream(stream []byte)
```
Keystream fills stream with cryptographically secure pseudorandom bytes from
x's key stream when a random key and iv are used. Keystream panics when the
ChaCha key stream is exhausted after producing 1.2 zettabytes.

## func 
```go
func (x *ChaCha20_ctx) Read(b []byte) (int, error)
```
Read fills b with cryptographically secure pseudorandom bytes from x's key
stream when a random key and iv are used. Read implements the io.Reader
interface. Read returns io.EOF when the key stream is exhausted after
producing 1.2 zettabytes. It will panic if called with the the same x after
io.EOF is returned, unless x is re-initialized.

## func 
```go
func (x *ChaCha20_ctx) Seek(n uint64)
```
Seek moves x directly to 64-byte block number n in constant time. Seek(0)
sets x back to its initial state.

## func 
```go
func (x *ChaCha20_ctx) SetRounds(r int)
```
SetRounds sets the number of rounds used by Encrypt, Decrypt, Read,
XORKeyStream and Keystream for a ChaCha20 context. The valid values for
r are 8, 12 and 20. SetRounds panics with any other value. ChaCha20's
default number of rounds is 20. Smaller r values are likely less secure but
are faster. ChaCha8 requires 8 rounds, ChaCha12 requires 12 and ChaCha20
requires 20.

## func 
```go
func (x *ChaCha20_ctx) XORKeyStream(dst, src []byte)
```
XORKeyStream implements the crypto/cipher.Stream interface. XORKeyStream
XORs src bytes with ChaCha's key stream and puts the result in dst.
XORKeyStream panics if len(dst) is less than len(src), or when the ChaCha
key stream is exhausted after producing 1.2 zettabytes.


