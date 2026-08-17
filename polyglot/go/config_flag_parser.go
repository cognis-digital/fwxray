package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// FlagType represents the data type of a configuration flag
type FlagType int

const (
	TypeUnknown FlagType = iota
	TypeString
	TypeInt
	TypeBool
	TypeFloat
	TypeHex
	TypeBinary
	TypeCert // Certificate or key material
)

// FlagMetadata holds additional information about a parsed flag
type FlagMetadata struct {
	Name        string   `json:"name"`
	Value       string   `json:"value,omitempty"`
	Original    string   `json:"original,omitempty"`
	Type        FlagType `json:"type"`
	Description  string   `json:"description,omitempty"`
	LineNum     int      `json:"line_num,omitempty"`
	Section     string   `json:"section,omitempty"`
	KeyPath     []string `json:"key_path,omitempty"`
	IsChanged   bool     `json:"is_changed,omitempty"`
	OldValue    string   `json:"old_value,omitempty"`
}

// ConfigDiffResult represents the result of comparing two firmware configs
type ConfigDiffResult struct {
	AddedFlags      []FlagMetadata `json:"added_flags"`
	RemovedFlags    []FlagMetadata `json:"removed_flags"`
	ModifiedFlags   []FlagMetadata `json:"modified_flags"`
	UnchangedCount  int            `json:"unchanged_count"`
	TotalFlags      int            `json:"total_flags"`
	EntropyRegions  []EntropyRegion `json:"entropy_regions,omitempty"`
}

// EntropyRegion represents a detected region of high-entropy data (likely certs/keys)
type EntropyRegion struct {
	StartOffset   uint64    `json:"start_offset"`
	EndOffset     uint64    `json:"end_offset"`
	EntropyScore  float64   `json:"entropy_score"`
	Type          string    `json:"detected_type,omitempty"`
	Confidence    float64   `json:"confidence"`
}

// ConfigParser handles parsing of various firmware configuration formats
type ConfigParser struct {
	data       []byte
	filePath   string
	lineOffset int
}

// NewConfigParser creates a new parser instance
func NewConfigParser(data []byte, filePath string) *ConfigParser {
	return &ConfigParser{
		data:     data,
		filePath: filePath,
	}
}

// Parse attempts to auto-detect and parse the configuration format
func (p *ConfigParser) Parse() (*ConfigDiffResult, error) {
	if len(p.data) == 0 {
		return nil, fmt.Errorf("empty input data")
	}

	result := &ConfigDiffResult{
		TotalFlags:    0,
		UnchangedCount: 0,
	}

	// Auto-detect format and parse accordingly
	var flags []FlagMetadata
	var err error

	parsedFormat, formatName := p.autoDetectFormat()
	switch parsedFormat {
	case FormatJSON:
		flags, err = p.parseJSON()
	case FormatXML:
		flags, err = p.parseXML()
	case FormatINI:
		flags, err = p.parseINI()
	case FormatKV:
		flags, err = p.parseKeyValue()
	default:
		return nil, fmt.Errorf("unknown format detected: %s", formatName)
	}

	if err != nil {
		return nil, fmt.Errorf("parsing error: %w", err)
	}

	result.Flags = flags
	result.TotalFlags = len(flags)

	// Detect entropy regions in binary data
	result.EntropyRegions = p.detectEntropyRegions()

	return result, nil
}

// autoDetectFormat determines the most likely format of the configuration
func (p *ConfigParser) autoDetectFormat() (FormatType, string) {
	data := bytes.TrimSpace(p.data)

	// Check for JSON
	if len(data) >= 4 && string(data[:1]) == "{" {
		var temp interface{}
		if err := json.Unmarshal(data, &temp); err == nil {
			return FormatJSON, "json"
		}
	}

	// Check for XML
	if len(data) >= 5 && string(data[:2]) == "<?x" || 
	   (len(data) >= 4 && string(data[:1]) == "<" && strings.Contains(string(data), "</")) {
		var temp interface{}
		if err := xml.Unmarshal(data, &temp); err == nil {
			return FormatXML, "xml"
		}
	}

	// Check for INI (look for [section] headers)
	hasINIHeaders := false
	scanner := bufio.NewScanner(bytes.NewReader(p.data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 && !strings.HasPrefix(line, ";") && !strings.HasPrefix(line, "#") {
			if strings.Contains(line, "[") && strings.Contains(line, "]") {
				hasINIHeaders = true
				break
			}
		}
	}

	if hasINIHeaders {
		return FormatINI, "ini"
	}

	// Default to key-value format for plain text configs
	return FormatKV, "key_value"
}

// parseJSON handles JSON configuration parsing
func (p *ConfigParser) parseJSON() ([]FlagMetadata, error) {
	var flags []FlagMetadata
	
	// Try unmarshaling into a generic map first
	var rawMap map[string]interface{}
	if err := json.Unmarshal(p.data, &rawMap); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	p.extractJSONFlags(rawMap, "", &flags)
	
	// Detect and mark certificate regions in JSON values
	flags = p.markCertRegions(flags, p.data)

	return flags, nil
}

// extractJSONFlags recursively extracts flags from nested JSON structures
func (p *ConfigParser) extractJSONFlags(node interface{}, path string, flags *[]FlagMetadata) {
	switch v := node.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := append([]string{key}, path...)
			
			if flagMap, ok := value.(map[string]interface{}); ok {
				// Check for common config field names
				if isConfigField(key) || len(flagMap) > 0 {
					p.extractJSONFlags(flagMap, newPath, flags)
				} else if valStr, ok := flagMap["value"].(string); ok {
					flags = append(*flags, FlagMetadata{
						Name:       strings.Join(newPath, "."),
						Value:      valStr,
						KeyPath:    newPath,
						Type:       TypeString,
						Description: p.inferDescription(key, newPath),
					})
				} else if flagVal, ok := flagMap["flag"].(string); ok {
					flags = append(*flags, FlagMetadata{
						Name:       strings.Join(newPath, "."),
						Value:      flagVal,
						KeyPath:    newPath,
						Type:       TypeBool,
						Description: "boolean flag",
					})
				}
			} else if valStr, ok := value.(string); ok {
				flags = append(*flags, FlagMetadata{
					Name:      strings.Join(newPath, "."),
					Value:     valStr,
					KeyPath:   newPath,
					Type:      TypeString,
					Description: p.inferDescription(key, newPath),
				})
			} else if numVal, ok := value.(float64); ok {
				intVal := int(numVal)
				flags = append(*flags, FlagMetadata{
					Name:   strings.Join(newPath, "."),
					Value:  strconv.Itoa(intVal),
					KeyPath: newPath,
					Type:   TypeInt,
				})
			} else if boolVal, ok := value.(bool); ok {
				flags = append(*flags, FlagMetadata{
					Name:      strings.Join(newPath, "."),
					Value:     strconv.FormatBool(boolVal),
					KeyPath:   newPath,
					Type:      TypeBool,
				})
			}
		}

	case []interface{}:
		for i, item := range v {
			newPath := append([]string{strconv.Itoa(i)}, path...)
			p.extractJSONFlags(item, newPath, flags)
		}
	}
}

// isConfigField checks if a field name suggests it's part of the config structure
func isConfigField(name string) bool {
	configKeywords := map[string]bool{
		"config": true, "cfg": true, "settings": true, "options": true,
		"params": true, "parameters": true, "flags": true, "features": true,
		"enabled": true, "disabled": true, "active": true, "mode": true,
	}
	
	lowerName := strings.ToLower(name)
	for keyword := range configKeywords {
		if lowerName == keyword || strings.Contains(lowerName, keyword) {
			return true
		}
	}
	return false
}

// inferDescription provides a human-readable description for the flag
func (p *ConfigParser) inferDescription(key string, path []string) string {
	description := "Configuration parameter"
	
	lowerKey := strings.ToLower(key)
	switch lowerKey {
	case "enabled", "active":
		return "toggle/activation flag"
	case "mode", "profile":
		return "operational mode selection"
	case "timeout", "interval", "period":
		return "timing parameter (seconds)"
	case "port", "ip", "address", "host":
		return "network endpoint configuration"
	case "cert", "key", "pem", "ssl", "tls":
		return "security certificate/credential"
	case "debug", "verbose", "trace":
		return "logging/debugging level"
	case "path", "directory", "root":
		return "filesystem path configuration"
	default:
		if len(path) > 0 {
			description = fmt.Sprintf("Nested config at %s", strings.Join(path, "."))
		}
	}
	
	return description
}

// parseXML handles XML configuration parsing
func (p *ConfigParser) parseXML() ([]FlagMetadata, error) {
	var flags []FlagMetadata
	
	type xmlNode struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
		Type  string `xml:"type"`
	}

	var root xmlNode
	if err := xml.Unmarshal(p.data, &root); err != nil {
		return nil, fmt.Errorf("invalid XML: %w", err)
	}

	p.extractXMLFlags(root, "", &flags)
	
	flags = p.markCertRegions(flags, p.data)
	
	return flags, nil
}

// extractXMLFlags recursively extracts flags from nested XML structures
func (p *ConfigParser) extractXMLFlags(node xmlNode, path string, flags *[]FlagMetadata) {
	if node.Name == "flag" || node.Name == "param" || node.Name == "setting" {
		flagType := TypeString
		if t, err := strconv.ParseInt(node.Type, 10, 64); err == nil {
			switch int(t) {
			case 0:
				flagType = TypeBool
			case 1:
				flagType = TypeInt
			case 2:
				flagType = TypeFloat
			}
		}

		flags = append(*flags, FlagMetadata{
			Name:       node.Name,
			Value:      node.Value,
			KeyPath:    []string{node.Name},
			Type:       flagType,
			Description: p.inferDescription(node.Name, []string{}),
		})
	}

	if len(node.Child) > 0 {
		for _, child := range node.Child {
			p.extractXMLFlags(child, path+node.Name+".", flags)
		}
	}
}

// parseINI handles INI-style configuration parsing
func (p *ConfigParser) parseINI() ([]FlagMetadata, error) {
	var flags []FlagMetadata
	currentSection := "global"
	
	scanner := bufio.NewScanner(bytes.NewReader(p.data))
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for section header
		if strings.Contains(line, "[") && strings.Contains(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			
			// Remove quotes if present
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			   (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}

			flags = append(flags, FlagMetadata{
				Name:       key,
				Value:      value,
				KeyPath:    []string{currentSection, key},
				Type:       TypeString,
				Description: p.inferDescription(key, []string{}),
				LineNum:    lineNum,
			})

			// Check for boolean values
			if strings.ToLower(value) == "true" || strings.ToLower(value) == "false" {
				flags[len(flags)-1].Type = TypeBool
			}

			// Try to parse as integer
			if intVal, err := strconv.Atoi(value); err == nil && len(value) <= 20 {
				flags[len(flags)-1].Type = TypeInt
			}
		}
	}

	return flags, scanner.Err()
}

// parseKeyValue handles plain key=value format (fallback parser)
func (p *ConfigParser) parseKeyValue() ([]FlagMetadata, error) {
	var flags []FlagMetadata
	
	scanner := bufio.NewScanner(bytes.NewReader(p.data))
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			
			// Remove quotes if present
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			   (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}

			flags = append(flags, FlagMetadata{
				Name:       key,
				Value:      value,
				KeyPath:    []string{"kv", key},
				Type:       TypeString,
				Description: "Plain key-value configuration",
				LineNum:    lineNum,
			})

			if strings.ToLower(value) == "true" || strings.ToLower(value) == "false" {
				flags[len(flags)-1].Type = TypeBool
			}

			if intVal, err := strconv.Atoi(value); err == nil && len(value) <= 20 {
				flags[len(flags)-1].Type = TypeInt
			}
		}
	}

	return flags, scanner.Err()
}

// markCertRegions identifies and marks certificate/key regions in parsed data
func (p *ConfigParser) markCertRegions(flags []FlagMetadata, rawData []byte) []FlagMetadata {
	var certRegexes = []*regexp.Regexp{
		regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
		regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		regexp.MustCompile(`-----BEGIN PUBLIC KEY-----`),
		regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
	}

	var certRegions []EntropyRegion

	for _, re := range certRegexes {
		matches := re.FindAllIndex(rawData, -1)
		for i, match := range matches {
			if len(matches) > 0 && i < len(matches)-1 {
				endOffset := matches[i+1][0]
			} else {
				endOffset := match[1] + 64 // Approximate cert length
			}

			certRegions = append(certRegions, EntropyRegion{
				StartOffset:   uint64(match[0]),
				EndOffset:     endOffset,
				EntropyScore:  0.95,
				Type:          "certificate",
				Confidence:    0.98,
			})
		}
	}

	// Mark flags that fall within cert regions
	for i := range flags {
		if len(flags[i].Value) > 0 {
			startPos := strings.Index(string(rawData), flags[i].Value)
			if startPos >= 0 && startOffsetWithinCert(startPos, certRegions) {
				flags[i].Type = TypeCert
				flags[i].Description = "Certificate/key material"
			}
		}
	}