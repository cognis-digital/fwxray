package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Section represents a logical region within the firmware image
type Section struct {
	Name    string
	Start   int64
	End     int64
	Type    SectionType
	Size    int64
}

// SectionType defines categories of content we track
type SectionType uint8

const (
	SectionUnknown SectionType = iota
	SectionCode
	SectionData
	SectionConfig
	SectionCert
	SectionEntropy
)

// Change represents a detected difference between two images
type Change struct {
	Type      string
	Offset    int64
	Size      int64
	ImageA    string // Source image (old)
	ImageB    string // Target image (new)
	DiffType  DiffType
}

// DiffType describes the nature of a change
type DiffType uint8

const (
	DiffAdded     DiffType = iota // Present in B, not in A
	DiffRemoved                   // Present in A, not in B
	DiffModified                  // Content changed at same offset
)

// ConfigFlag represents a configuration flag/parameter
type ConfigFlag struct {
	Name    string
	Offset  int64
	Value   []byte
	Type    FlagType
}

// FlagType defines how to interpret config values
type FlagType uint8

const (
	FlagBool FlagType = iota
	FlagInt
	FlagString
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: fwxray diff <image1> <image2>")
		fmt.Println("       fwxray diff --help")
		os.Exit(0)
	}

	var imageA, imageB string
	var help bool

	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--help" || arg == "-h" {
			help = true
			continue
		}
		imageA = arg
		i++
		imageB = arg
		break
	}

	if help {
		printHelp()
		return
	}

	if imageA == "" || imageB == "" {
		fmt.Println("Error: both images must be specified")
		os.Exit(1)
	}

	oldImg, err := os.Open(imageA)
	if err != nil {
		fmt.Printf("Error opening %s: %v\n", imageA, err)
		os.Exit(1)
	}
	defer oldImg.Close()

	newImg, err := os.Open(imageB)
	if err != nil {
		fmt.Printf("Error opening %s: %v\n", imageB, err)
		os.Exit(1)
	}
	defer newImg.Close()

	oldSize, _ := io.Seekable(oldImg).Seek(0, 2)
	newSize, _ := io.Seekable(newImg).Seek(0, 2)

	fmt.Printf("Comparing %s (%d bytes) vs %s (%d bytes)\n", imageA, oldSize, imageB, newSize)

	// Step 1: Parse sections from both images
	oldSections := parseSections(oldImg, "old")
	newSections := parseSections(newImg, "new")

	// Step 2: Compare sections and collect changes
	var changes []Change

	changes = compareSections(oldSections, newSections)

	// Step 3: Analyze config flags
	oldFlags := extractConfigFlags(oldImg, oldSections)
	newFlags := extractConfigFlags(newImg, newSections)
	flagChanges := compareFlags(oldFlags, newFlags)

	// Step 4: Detect certificates
	oldCerts := detectCertificates(oldImg, oldSections)
	newCerts := detectCertificates(newImg, newSections)
	certChanges := compareCertificates(oldCerts, newCerts)

	// Step 5: Analyze entropy regions
	oldEntropy := analyzeEntropy(oldImg, oldSections)
	newEntropy := analyzeEntropy(newImg, newSections)
	entropyChanges := compareEntropy(oldEntropy, newEntropy)

	// Step 6: Generate final report
	report := generateReport(changes, flagChanges, certChanges, entropyChanges, imageA, imageB)

	fmt.Println(report)

	// Exit with appropriate code
	if len(changes) > 0 {
		os.Exit(1) // Non-zero exit indicates differences found
	}
}

func printHelp() {
	fmt.Println(`fwxray - Firmware Image Diff Tool

Usage: fwxray diff <image1> <image2> [--output <file>]

Compares two firmware images and reports:
  • New/removed code sections
  • Modified configuration flags
  • Added/changed certificates
  • Shifted entropy regions

Exit codes:
  0 - Images are identical
  1 - Differences found`)
}

// parseSections attempts to identify logical sections in a firmware image
func parseSections(f *os.File, label string) []Section {
	sections := make([]Section, 0)

	// Read file header info
	info, _ := f.Stat()
	size := info.Size()

	// Default: treat entire file as unknown if no headers detected
	if size == 0 {
		return sections
	}

	// Try to detect common firmware formats
	format, offset, err := detectFormat(f)
	if err != nil {
		fmt.Printf("Warning: format detection failed for %s: %v\n", label, err)
		sections = append(sections, Section{
			Name:  "unknown",
			Start: 0,
			End:   size - 1,
			Type:  SectionUnknown,
			Size:  size,
		})
		return sections
	}

	fmt.Printf("Detected format for %s: %s\n", label, format)

	// Parse based on detected format
	switch format {
	case "ELF":
		parseELF(f, &sections)
	case "PE/COFF":
		parsePE(f, &sections)
	default:
		// For raw binary or unknown formats, use heuristic parsing
		parseRawHeuristic(f, &sections, size)
	}

	return sections
}

// detectFormat tries to identify the firmware image format
func detectFormat(f *os.File) (string, int64, error) {
	header := make([]byte, 1024)
	n, err := f.Read(header)
	if n < 512 || err != nil {
		return "raw", 0, fmt.Errorf("truncated header: %v", err)
	}

	// Check ELF magic
	if bytes.Equal(header[0:16], []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF", 0, nil
	}

	// Check PE/COFF signature
	if bytes.Equal(header[0:4], []byte("MZ")) {
		return "PE/COFF", 0, nil
	}

	// Check for common firmware headers (generic)
	signatures := map[string]int64{
		"UBOOT":    0x55424F4F, // "UBOF" little-endian
		"LINUX":    0x4C494E55, // "LINU" little-endian
		"QNX":      0x514E5830, // "QN X0"
	}

	for name, sig := range signatures {
		if binary.LittleEndian.Uint32(header[0:4]) == sig {
			return name, 0, nil
		}
	}

	// Check for embedded certificates (often at end of file)
	if certCount := countCertificates(header); certCount > 0 {
		return "raw+certs", 0, nil
	}

	return "raw", 0, nil
}

// parseELF handles ELF format firmware images
func parseELF(f *os.File, sections *[]Section) {
	header := make([]byte, 512)
	f.Read(header)

	var elfHeader struct {
		Class    uint8
		Endian   uint8
		Version  uint16
		Type     uint16
		Machine  uint16
		Entry    uint32
		PhOff    uint32
		SzPhEnt  uint16
		Nph       uint16
	}

	binary.Read(bytes.NewReader(header[:64]), binary.LittleEndian, &elfHeader)

	if elfHeader.Class != 2 { // ELF64
		return
	}

	// Parse program headers for section info
	for i := int64(0); i < int64(elfHeader.Nph); i++ {
		poffset := int64(elfHeader.PhOff) + (i * int64(elfHeader.SzPhEnt))
		if poffset >= 512 {
			break
		}

		var ph struct {
			Type   uint32
			Offset uint64
			Vaddr  uint64
			Size   uint64
			Memsz  uint64
			Flags  uint64
		}

		binary.Read(bytes.NewReader(header[poffset:poffset+56]), binary.LittleEndian, &ph)

		switch ph.Type {
		case 1: // PT_LOAD
			if ph.Size > 0 && ph.Memsz > 0 {
				*sections = append(*sections, Section{
					Name:  fmt.Sprintf("load_seg_%d", i),
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionCode,
					Size:  ph.Memsz,
				})
			}
		case 2: // PT_DYNAMIC (often contains config/flags)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "dynamic",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionData,
					Size:  ph.Memsz,
				})
			}
		case 3: // PT_NOTE (often contains notes/flags)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "notes",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 4: // PT_GNU_RELRO (read-only data)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "relro",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionData,
					Size:  ph.Memsz,
				})
			}
		case 5: // PT_GNU_EH_FRAME (exception handling)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "eh_frame",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionCode,
					Size:  ph.Memsz,
				})
			}
		case 6: // PT_GNU_STACK (stack segment)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "stack",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionData,
					Size:  ph.Memsz,
				})
			}
		case 7: // PT_GNU_PROPERTY (properties/attributes)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 8: // PT_GNU_RELAC (relocation)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "relac",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionData,
					Size:  ph.Memsz,
				})
			}
		case 9: // PT_GNU_PROPERTY_V2 (v2 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v2",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 10: // PT_GNU_PROPERTY_V3 (v3 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v3",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 11: // PT_GNU_PROPERTY_V4 (v4 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v4",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 12: // PT_GNU_PROPERTY_V5 (v5 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v5",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 13: // PT_GNU_PROPERTY_V6 (v6 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v6",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 14: // PT_GNU_PROPERTY_V7 (v7 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v7",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 15: // PT_GNU_PROPERTY_V8 (v8 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v8",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 16: // PT_GNU_PROPERTY_V9 (v9 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v9",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 17: // PT_GNU_PROPERTY_V10 (v10 properties)
			if ph.Size > 0 {
				*sections = append(*sections, Section{
					Name:  "property_v10",
					Start: int64(ph.Offset),
					End:   int64(ph.Offset + ph.Size - 1),
					Type:  SectionConfig,
					Size:  ph.Memsz,
				})
			}
		case 18: // PT_GNU_PROPERTY_V11 (v1