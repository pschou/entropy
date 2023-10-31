package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"time"

	"github.com/jlowellwofford/entropy"
)

var (
	step    = flag.Duration("interval", time.Second, "between entropy avail checks")
	min     = flag.Int("min", 3000, "minimum entropy to maintain")
	debug   = flag.Bool("debug", false, "turn on debug")
	version string
	sum     hash.Hash
)

func main() {
	fmt.Println("Entropy builder - maintain a certain level of entropy, Version", version, "(https://github.com/pschou/entropy)")
	flag.Parse()
	for {
		for {
			if cnt, err := entropy.GetEntCnt(); err != nil {
				log.Fatal("failed to get entropy: %v", err)
			} else {
				if *debug {
					fmt.Println("cnt", cnt)
				}
				if cnt > *min {
					break
				}
			}
			sum = sha256.New()
			for _, f := range []string{"/proc/meminfo", "/proc/self/maps", "/proc/self/smaps", "/proc/interrupts", "/proc/diskstats", "/proc/self/stat"} {
				t()
				if fh, err := os.Open(f); err == nil {
					io.Copy(sum, fh)
				}
			}
			buf := sum.Sum(nil)
			bits := len(buf) * 8
			if *debug {
				fmt.Printf("%x", sum)
				fmt.Printf("adding %d bytes with %d bits of entropy\n", len(buf), bits)
			}
			if err := entropy.AddEntropy(bits, buf); err != nil {
				log.Fatal("failed to add entropy: %v", err)
			}
		}
		time.Sleep(*step)
	}
}

var b = make([]byte, 8)

func t() {
	ns := time.Now().Nanosecond()
	binary.LittleEndian.PutUint64(b, uint64(ns))
	sum.Write(b)
}
