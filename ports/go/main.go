// Go port of the fwxray CORE check: Shannon entropy + magic-signature carving
// over a firmware image. Passive, offline, single static binary, zero deps.
// Output JSON shape matches the Python reference (path/size/entropy/sections).
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
)

type Section struct {
	Label   string  `json:"label"`
	Offset  int     `json:"offset"`
	Entropy float64 `json:"entropy"`
}

type Report struct {
	Tool     string    `json:"tool"`
	Path     string    `json:"path"`
	Size     int       `json:"size"`
	Entropy  float64   `json:"entropy"`
	Sections []Section `json:"sections"`
}

var magics = []struct {
	sig   []byte
	label string
}{
	{[]byte{0x1f, 0x8b, 0x08}, "gzip"},
	{[]byte("BZh"), "bzip2"},
	{[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, "xz"},
	{[]byte{0x28, 0xb5, 0x2f, 0xfd}, "zstd"},
	{[]byte("PK\x03\x04"), "zip"},
	{[]byte("hsqs"), "squashfs(le)"},
	{[]byte("UBI#"), "ubi"},
	{[]byte("ANDROID!"), "android_boot"},
	{[]byte("\x7fELF"), "elf"},
	{[]byte("-----BEGIN "), "pem"},
}

// ShannonEntropy returns bits/byte (0..8); empty input is 0.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			ent -= p * math.Log2(p)
		}
	}
	return math.Round(ent*10000) / 10000
}

func indexOf(data, sig []byte, from int) int {
	for i := from; i+len(sig) <= len(data); i++ {
		match := true
		for j := range sig {
			if data[i+j] != sig[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// CarveSections finds magic-signature offsets, deduplicated and sorted.
func CarveSections(data []byte) []Section {
	type hit struct {
		off   int
		label string
	}
	var hits []hit
	for _, m := range magics {
		start := 0
		for {
			idx := indexOf(data, m.sig, start)
			if idx == -1 {
				break
			}
			hits = append(hits, hit{idx, m.label})
			start = idx + 1
		}
	}
	// insertion sort by offset (small slices)
	for i := 1; i < len(hits); i++ {
		for j := i; j > 0 && hits[j].off < hits[j-1].off; j-- {
			hits[j], hits[j-1] = hits[j-1], hits[j]
		}
	}
	var secs []Section
	last := -256
	for _, h := range hits {
		if h.off-last < 256 {
			continue
		}
		last = h.off
		end := h.off + 1024
		if end > len(data) {
			end = len(data)
		}
		secs = append(secs, Section{h.label, h.off, ShannonEntropy(data[h.off:end])})
	}
	if secs == nil {
		secs = []Section{}
	}
	return secs
}

func Inspect(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	return Report{
		Tool:     "fwxray",
		Path:     path,
		Size:     len(data),
		Entropy:  ShannonEntropy(data),
		Sections: CarveSections(data),
	}, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fwxray <firmware-image>")
		os.Exit(2)
	}
	rep, err := Inspect(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(out))
}
