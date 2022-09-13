<!-- title: ChaCha20 Read Me -->
<!-- $Id: ReadMe.md,v 1.21 2022-09-13 11:13:38-04 ron Exp $ -->

# ChaCha20 public domain encryption and decryption in Go

Public domain chacha20.go implements the ChaCha20 encryption and decryption
algorithm by D. J. Bernstein.  chacha20.go is derived from Bernstein's public
domain [ref implementation](https://cr.yp.to/chacha.html).
chacha20.go and chacha20_test.go are in the
[public domain](https://creativecommons.org/publicdomain/zero/1.0/)
and may be used for any purpose.

ChaCha20 has been
[widely adopted](https://en.wikipedia.org/wiki/Salsa20#ChaCha20_adoption).

Example use:

```go
import "chacha20"
import "crypto/rand"
// ...
var m = []byte("This is a test.")    // put a real message in m here
c := make([]byte, len(m))
key := make([]byte, 32)    // 16 is acceptable; 32 is recommended
rand.Read(key)          // use your real key here
iv := make([]byte, 8)   // must be 8  
rand.Read(iv)           // use your real initialization vector here
ctx := chacha20.New(key, iv) // create a chacha20 context
ctx.Encrypt(m, c)       // encrypt m into c
// ...
ctx = chacha20.New(key, iv)   // must use same key/iv as encrypt to decrypt
ctx.Decrypt(c, m)       // decrypt c back into m
// ...
```

chacha20.go can also perform as ChaCha8 and ChaCha12 by using
SetRounds(8) or SetRounds(12).
