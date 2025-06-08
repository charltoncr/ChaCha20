////
// chacha20TuneParallel.go - Test varying blocksPerChunk for speed.
// $Id: chacha20TuneParallel.go,v 1.18 2025-06-08 16:04:54-04 ron Exp $
//
// Usage: go run chacha20TuneParallel.go
//
// Typical output is at EOF.
////

package main

import (
	"chacha20"
	"crypto/rand"
	"fmt"

	u "util"
)

var loopCount = 60

func main() {
	key := make([]byte, 32)
	iv := make([]byte, 8)
	data := make([]byte, 7e7)
	rand.Read(key)
	rand.Read(iv)
	rand.Read(data)
	ctx := chacha20.New(key, iv)
	n := []int{25, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600}
	byteCount := loopCount * len(data)

	fmt.Printf("Total bytes processed per row is %s in %d calls.\n\n",
		u.AddSepsNum(byteCount), loopCount)
	fmt.Printf("                               Minimun bytes\n")
	fmt.Printf("BlocksPerChunk    Speed     for parallel process\n")
	fmt.Printf("--------------  ---------   --------------------\n")

	// Measure various BPC parallel processing speeds.
	for i := range len(n) {
		ctx.TuneParallel(n[i], 0)
		start := u.Secs()
		for j := 0; j < loopCount; j++ {
			ctx.Encrypt(data, data)
		}
		delta := u.Secs() - start
		x, symbol := u.Scale(float64(byteCount) / delta)
		fmt.Printf("      %3d     %6.2f %sB/s  ", n[i], x, symbol)
		fmt.Printf("%12s\n", u.AddSepsNum(64*2*n[i]))
	}

	// Measure non-parallel processing speed.
	data = make([]byte, 2*459e6)
	rand.Read(data)
	ctx.UseParallel(false)
	start := u.Secs()
	ctx.Encrypt(data, data)
	delta := u.Secs() - start
	x, symbol := u.Scale(float64(len(data)) / delta)
	fmt.Printf("\nNon-parallel speed is %6.2f %sB/s.\n", x, symbol)
}

/*
2025-06-05, 3.504 GHz Mac M2 w/12 processors, chacha20 v6.81:

~/go/src/chacha20/tuning $ go run chacha20TuneParallel.go
Total bytes processed per row is 4,200,000,000 in 60 calls.

                               Minimun bytes
BlocksPerChunk   Speed     for parallel process
--------------  ---------  --------------------
       25       1.49 GB/s         3,200
       50       2.65 GB/s         6,400
      100       3.65 GB/s        12,800
      150       3.82 GB/s        19,200
      200       4.05 GB/s        25,600
      250       4.25 GB/s        32,000
      300       4.34 GB/s        38,400
      350       4.45 GB/s        44,800
      400       4.51 GB/s        51,200
      450       4.54 GB/s        57,600
      500       4.61 GB/s        64,000
      550       4.59 GB/s        70,400
      600       4.65 GB/s        76,800

Non-parallel speed is 459.03 MB/s.
~/go/src/chacha20/tuning $
*/
