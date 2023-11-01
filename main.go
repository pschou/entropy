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
	step      = flag.Duration("interval", time.Second/4, "between entropy avail checks")
	min       = flag.Int("min", 1000, "minimum entropy to maintain")
	dutyCycle = flag.Int("duty", 1000, "create up to these many seeds per interval")
	debug     = flag.Bool("debug", false, "turn on debug")
	version   string
	sum       hash.Hash
	buf       = []byte{}
	//maxSeen, atMaxSeen int
)

func main() {
	fmt.Println("Entropy builder - maintain a certain level of entropy, Version", version,
		"(https://github.com/pschou/entropy)")
	flag.Parse()
	sum = sha256.New() // Create a new hash

	if err := entropy.AddEntropy(0, buf); err != nil {
		log.Fatalf("failed to add entropy: %v", err)
	}

	for { // Loop indefinitely
		for j := 0; j < *dutyCycle; j++ { // Loop until the minimum entropy is met
			// Get the current entropy state
			if cnt, err := entropy.GetEntCnt(); err != nil {
				log.Fatalf("failed to get entropy: %v", err)
			} else {
				if *debug {
					log.Println("entropy:", cnt)
				}
				if cnt >= *min {
					break // Minimum has been met, go to outer loop to sleep
				}
			}

			// Loop over a bunch of kernel handles and copy them to the hash
			for _, f := range []string{"/proc/meminfo", "/proc/self/maps",
				"/proc/self/smaps", "/proc/interrupts", "/proc/diskstats", "/proc/self/stat"} {
				t() // Add some nanosecond bits
				if fh, err := os.Open(f); err == nil {
					io.Copy(sum, fh)
					fh.Close()
				}
			}

			buf = sum.Sum(nil) // Do the hash
			sum = sha256.New() // Create a new hash
			bits := len(buf) * 8
			if *debug {
				log.Printf("adding %d bytes / %d bits: %x\n", len(buf), bits, buf)
			}
			if err := entropy.AddEntropy(bits, buf); err != nil {
				log.Fatalf("failed to add entropy: %v", err)
			}
		}
		t() // Add some nanosecond bits
		time.Sleep(*step)
	}
}

var b = make([]byte, 8)

// Get the current nanoseconds from the clock and add this to the hash
func t() {
	ns := time.Now().Nanosecond()
	binary.LittleEndian.PutUint64(b, uint64(ns))
	sum.Write(b)
}
