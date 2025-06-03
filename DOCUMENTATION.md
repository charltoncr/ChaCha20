```go
package chacha20 // import "chacha20"
```
```go
Package chacha20 provides public domain ChaCha20 encryption and
decryption. It is derived from public domain file chacha[-ref].c
at <https://cr.yp.to/chacha.html>. It implements the io.Reader and
crypto/cipher.Stream interfaces, as well as several other methods.
```
```go
On long byte slices (>25,600 bytes) ChaCha20 provides speed approximating that
of hardware-implemented AES encryption.
```
```go
Some chacha20 methods panic when a ChaCha key stream is exhausted after
producing about 1.2 zettabytes if io.EOF is not honored. A zettabyte is so much
data that it is nearly impossible to generate that much. At 1 ns/block it would
take 584+ years to generate 1.2 zettabytes.
```
```go
Some chacha20 methods also panic when the method's destination is shorter than
its source, or when an invalid length key or iv is given, or when an invalid
number of rounds is specified.
```
```go
The Encrypt method processes slices over about 25,600 bytes long with parallel
processing at between 2 and 9 times the speed of mono-processing. All chacha20
methods share Encrypt's increased speed on similarly long slices.
```
```go
Parallel processing can allocate up to 11,200 bytes of memory. If memory is
tight call NewSmallMemory() instead of New for a much smaller memory footprint.
Processing speed then will be dramatically slower for long byte slices.
As an alternative, TuneParallel can also adjust memory allocation vs speed for
parallel processing, achieving four times the speed of non-parallel processing
with a minimal memory footprint.
```
## TYPES

Ctx contains state information for a ChaCha20 context. Ctx implements the
io.Reader and the crypto/cipher.Stream interfaces.
```go
type Ctx struct {
	// Has unexported fields.
}
```
## func New
```go
func New(key, iv []byte) (ctx *Ctx)
```
New allocates a new ChaCha20 context and sets it up with the caller's key
and iv. The default number of rounds is 20. To use a different number of
rounds, call SetRounds also.

## func NewSmallMemory
```go
func NewSmallMemory(key, iv []byte) (ctx *Ctx)
```
NewSmallMemory allocates a context the same as New does but doesn't use
parallel processing. Processing speed will be dramtically slower and memory
use will be much less for long messages. The default number of rounds is 20.
To use a different number of rounds, call SetRounds also.

## func 
```go
func (x *Ctx) Decrypt(c, m []byte) (int, error)
```
Decrypt puts plaintext into m given ciphertext c. Any length is allowed for
c. Parameters m and c must overlap completely or not at all. Decrypt panics
if len(m) < len(c). len(m) can be larger than len(c). The message to be
decrypted can be processed in sequential segments with multiple calls to
Decrypt.

Decrypt returns io.EOF when the key stream is exhausted after producing
1.2 zettabytes. It will panic if called with the the same x after io.EOF is
returned, unless x has been re-initialized. The same key, iv and rounds used
to encrypt a message must be used to decrypt the message.

## func 
```go
func (x *Ctx) Encrypt(m, c []byte) (n int, err error)
```
Encrypt puts ciphertext into c given plaintext m. Any length is allowed for
m. Parameters m and c must overlap completely or not at all. Encrypt panics
if len(c) < len(m). len(c) can be greater than len(m). The message to be
encrypted can be processed in sequential segments with multiple calls to
Encrypt.

Encrypt returns io.EOF when the key stream is exhausted (extremely
improbable) after producing 1.2 zettabytes. It will panic if called with the
the same x after io.EOF is returned, unless x has been re-initialized.

The same key, iv and rounds used to encrypt a message must be used to
decrypt the message. Messages and Reads over about 25,600 bytes long will
be parallel processed 2-10 times as fast, unless NewSmallMemory is used to
allocate x.

## func 
```go
func (x *Ctx) GetCounter() (n uint64)
```
GetCounter returns x's block counter value.

## func 
```go
func (x *Ctx) IvSetup(iv []byte)
```
IvSetup sets initialization vector iv as a nonce for ChaCha20 context x.
It also calls Seek(0). IvSetup panics if len(iv) is not 8.

## func 
```go
func (x *Ctx) IvSetupUint64(n uint64)
```
IvSetupUint64 sets x's initialization vector (nonce) to the value in n.
It also calls Seek(0).

## func 
```go
func (x *Ctx) KeySetup(key []byte)
```
KeySetup sets up ChaCha20 context x with key. KeySetup panics if len(key) is
not 16 or 32. A key length of 32 is recommended.

## func 
```go
func (x *Ctx) Keystream(stream []byte)
```
Keystream fills stream with cryptographically secure pseudorandom bytes from
x's key stream when a random key and iv are used. Keystream panics when the
ChaCha key stream is exhausted after producing 1.2 zettabytes.

## func 
```go
func (x *Ctx) Read(b []byte) (int, error)
```
Read fills b with cryptographically secure pseudorandom bytes from x's
key stream when a random key and iv are used with x. Read implements the
io.Reader interface. Read returns io.EOF when the key stream is exhausted
after producing 1.2 zettabytes. It will panic if called with the the same x
after io.EOF is returned, unless IvSetup is called with a new value first.

## func 
```go
func (x *Ctx) Seek(n uint64)
```
Seek moves x directly to 64-byte block number n in constant time. Seek(0)
sets x back to its initial state.

## func 
```go
func (x *Ctx) SetRounds(r int)
```
SetRounds sets the number of rounds used by Encrypt, Decrypt, Read,
XORKeyStream and Keystream for a ChaCha20 context. The valid values for r:
8, 12 and 20. SetRounds panics with any other value. ChaCha20's default
number of rounds is 20. Smaller r values are likely less secure but are
faster. ChaCha8 requires 8 rounds, ChaCha12 requires 12 and ChaCha20
requires 20.

## func 
```go
func (x *Ctx) TuneParallel(BlocksPerGoroutine, MaxGoroutines int)
```
TuneParallel is not required for typical ChaCha20 use. In unusual
circumstances it allows adjustments to parallel processing parameters
to make time and space tradeoffs. Each Ctx instance has its own parallel
processing parameters. Defaults are equivalent to TuneParallel(200, 300).

TuneParallel has no effect on processing short messages, or when parallel
processing is disabled by calling UseParallel(false) or NewSmallMemory.

If BlocksPerGoroutine > 0 it sets how many ChaCha20 blocks of 64 bytes
are processed by each goroutine instance. Smaller values slow processing
generally, but allow shorter length messages to be processed in parallel,
thereby speeding up processing for them.

If MaxGoroutines > 0 it determines how many goroutines may run
simultaneously. Larger values will speed up processing somewhat,
also allowing more memory to be allocated at once. The default value, 300,
results in simultaneous allocation of 51,600 bytes. Maximum simultaneous
memory allocation is MaxGoroutines * 172. Go documentation recommends
liberty when issuing simultaneous goroutines, stating that 3,000 goroutines
are easily managed by the Go runtime.

To change only one parameter in a call use zero for other parameter.

With TuneParallel(50, 30) (allowing parallel processing of messages as short
as 6,400 bytes) ChaCha20 with parallel processing is 4.6 times as fast (2.1
GB/s vs 457 MB/s) as non-parallel processing on a 3.5 GHz Apple M2 with 12
processors. YMMV.

## func 
```go
func (x *Ctx) UseParallel(b bool)
```
UseParallel accepts a boolean to determine whether x uses parallel
processing. Parallel operation uses larger amounts of memory; if memory
is scarce call UseParallel with b false after calling New. False b will
result in dramatically slower speed for all ChaCha20 operations. Calling
UseParallel is not necessary if NewSmallMemory was used to instantiate x.

## func 
```go
func (x *Ctx) XORKeyStream(dst, src []byte)
```
XORKeyStream implements the crypto/cipher.Stream interface. XORKeyStream
XORs src bytes with ChaCha's key stream and puts the result in dst.
XORKeyStream panics if len(dst) is less than len(src), or when the ChaCha
key stream is exhausted after producing 1.2 zettabytes.


