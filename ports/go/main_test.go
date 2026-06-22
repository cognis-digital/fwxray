package main

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 0.001 }

func TestEntropyEmpty(t *testing.T) {
	if ShannonEntropy(nil) != 0.0 {
		t.Fatal("empty should be 0")
	}
}

func TestEntropyUniform(t *testing.T) {
	if ShannonEntropy([]byte{1, 1, 1, 1}) != 0.0 {
		t.Fatal("single-symbol entropy should be 0")
	}
}

func TestEntropyTwoSymbols(t *testing.T) {
	if !approx(ShannonEntropy([]byte{0, 1}), 1.0) {
		t.Fatalf("two equiprobable symbols should be 1.0, got %v", ShannonEntropy([]byte{0, 1}))
	}
}

func TestEntropyAllBytes(t *testing.T) {
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte(i)
	}
	if !approx(ShannonEntropy(buf), 8.0) {
		t.Fatalf("all 256 bytes should be 8.0, got %v", ShannonEntropy(buf))
	}
}

func TestCarveDetectsELF(t *testing.T) {
	data := append([]byte("\x7fELF"), make([]byte, 300)...)
	secs := CarveSections(data)
	if len(secs) != 1 || secs[0].Label != "elf" {
		t.Fatalf("expected one elf section, got %+v", secs)
	}
}

func TestCarveDetectsGzip(t *testing.T) {
	data := append([]byte{0x1f, 0x8b, 0x08}, make([]byte, 300)...)
	secs := CarveSections(data)
	if len(secs) != 1 || secs[0].Label != "gzip" {
		t.Fatalf("expected gzip, got %+v", secs)
	}
}

func TestCarveEmpty(t *testing.T) {
	if len(CarveSections(nil)) != 0 {
		t.Fatal("empty image should carve no sections")
	}
}

func TestCarveMinSpacing(t *testing.T) {
	// two ELF magics 10 bytes apart -> only the first survives min spacing
	data := make([]byte, 400)
	copy(data[0:], []byte("\x7fELF"))
	copy(data[10:], []byte("\x7fELF"))
	if len(CarveSections(data)) != 1 {
		t.Fatal("magics within 256 bytes should collapse to one section")
	}
}
