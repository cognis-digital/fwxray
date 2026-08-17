"""
polyglot/python/config_flag_parser.py

A robust configuration flag parser for firmware images.
Supports binary blobs, JSON, INI, TOML, XML, and hex dumps.
"""

import json
import os
import re
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple, Union


class FlagType(Enum):
    """Supported configuration flag types."""
    STRING = auto()
    INTEGER = auto()
    BOOLEAN = auto()
    FLOAT = auto()
    ARRAY = auto()
    OBJECT = auto()
    BLOB = auto()
    UNKNOWN = auto()


@dataclass
class ParsedFlag:
    """Represents a single parsed configuration flag."""
    name: str
    value: Any
    type_: FlagType = FlagType.STRING
    source: str = ""
    offset: int = 0
    length: int = 0
    
    def __str__(self) -> str:
        return f"{self.name}={repr(self.value)} ({self.type_})"


@dataclass
class ParseResult:
    """Container for all parsing results."""
    flags: List[ParsedFlag]
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def add_flag(self, flag: ParsedFlag):
        self.flags.append(flag)
    
    def has_errors(self) -> bool:
        return len(self.errors) > 0
    
    def summary(self) -> str:
        types = {}
        for f in self.flags:
            t = f.type_
            types[t] = types.get(t, 0) + 1
        
        type_names = {
            FlagType.STRING: "STRING",
            FlagType.INTEGER: "INT",
            FlagType.BOOLEAN: "BOOL",
            FlagType.FLOAT: "FLOAT",
            FlagType.ARRAY: "ARRAY",
            FlagType.OBJECT: "OBJ",
            FlagType.BLOB: "BLOB",
        }
        
        type_str = ", ".join(f"{n}={c}" for n, c in types.items())
        return f"Found {len(self.flags)} flags ({type_str})"


def _normalize_name(name: str) -> str:
    """Normalize flag names to a consistent format."""
    # Remove common prefixes/suffixes
    name = re.sub(r'^[0-9a-fA-F]{4,}_[^_]+_', '', name)  # Strip hex offsets
    name = re.sub(r'_([0-9a-fA-F]{2})$', '', name)  # Strip trailing byte
    
    # Clean up whitespace and special chars
    name = re.sub(r'[\s_\-\.]+', '_', name.strip())
    
    return name


def _detect_string_type(data: bytes, offset: int, length: int) -> Tuple[FlagType, str]:
    """Detect if a string is null-terminated or fixed-length."""
    try:
        # Check for null termination
        chunk = data[offset:offset + min(length, 256)]
        null_pos = chunk.find(b'\x00')
        
        if null_pos >= 0 and null_pos < len(chunk) - 1:
            return FlagType.STRING, chunk[:null_pos].decode('utf-8', errors='replace').strip()
        elif length <= 256:
            # Likely fixed-length string
            try:
                return FlagType.STRING, chunk.decode('utf-8', errors='replace').strip()
            except UnicodeDecodeError:
                pass
        
        # Try common encodings for null-terminated strings
        for encoding in ['ascii', 'latin-1', 'cp437']:
            try:
                decoded = chunk[:null_pos].decode(encoding) if null_pos < len(chunk) else chunk.decode(encoding, errors='replace')
                return FlagType.STRING, decoded.strip()
            except (UnicodeDecodeError, AttributeError):
                continue
        
        return FlagType.BLOB, chunk.hex()
    except Exception:
        return FlagType.BLOB, data[offset:offset+length].hex()


def _parse_binary_blob(data: bytes, offset: int = 0) -> ParseResult:
    """Parse binary blob for string flags and common patterns."""
    result = ParseResult(flags=[])
    
    # Look for null-terminated strings (most common in firmware configs)
    max_length = min(len(data), 65536)
    chunk_size = 4096
    
    pos = offset
    while pos < len(data):
        if pos + 256 > len(data):
            break
            
        # Find next null byte or end of chunk
        null_pos = data.find(b'\x00', pos)
        if null_pos == -1:
            null_pos = min(pos + chunk_size, len(data))
        
        length = null_pos - pos
        
        # Extract and decode string
        try:
            text = data[pos:null_pos].decode('utf-8', errors='replace').strip()
            
            if text and not text.startswith(('0x', '0X')):  # Skip hex-looking strings
                name, value = _detect_string_type(data, pos, length)
                
                flag = ParsedFlag(
                    name=_normalize_name(text),
                    value=value,
                    type_=name,
                    source="binary_blob",
                    offset=pos,
                    length=length
                )
                result.add_flag(flag)
        except Exception:
            pass
        
        pos = null_pos + 1
    
    return result


def _parse_json_config(data: bytes) -> ParseResult:
    """Parse JSON configuration data."""
    result = ParseResult(flags=[])
    
    try:
        obj = json.loads(data.decode('utf-8', errors='replace'))
        
        def extract_flags(obj: Any, prefix: str = "", depth: int = 0) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_prefix = f"{prefix}{key}_" if prefix else f"{key}_"
                    
                    # Recurse into nested objects
                    if isinstance(value, (dict, list)):
                        extract_flags(value, new_prefix, depth + 1)
                    elif isinstance(value, bool):
                        flag = ParsedFlag(
                            name=_normalize_name(new_prefix),
                            value=str(value).lower(),
                            type_=FlagType.BOOLEAN,
                            source="json_config"
                        )
                        result.add_flag(flag)
                    elif isinstance(value, (int, float)):
                        flag = ParsedFlag(
                            name=_normalize_name(new_prefix),
                            value=value,
                            type_=FlagType.INTEGER if isinstance(value, int) else FlagType.FLOAT,
                            source="json_config"
                        )
                        result.add_flag(flag)
                    elif isinstance(value, str):
                        # Check if it looks like a number or boolean
                        try:
                            if '.' in value:
                                flag = ParsedFlag(
                                    name=_normalize_name(new_prefix),
                                    value=float(value),
                                    type_=FlagType.FLOAT,
                                    source="json_config"
                                )
                                result.add_flag(flag)
                            elif value.lower() in ('true', 'false'):
                                flag = ParsedFlag(
                                    name=_normalize_name(new_prefix),
                                    value=value.lower(),
                                    type_=FlagType.BOOLEAN,
                                    source="json_config"
                                )
                                result.add_flag(flag)
                        except ValueError:
                            pass
            elif isinstance(obj, list):
                # Arrays are typically lists of strings or numbers
                for item in obj:
                    if isinstance(item, (int, float)):
                        flag = ParsedFlag(
                            name=_normalize_name(f"{prefix}array"),
                            value=item,
                            type_=FlagType.INTEGER if isinstance(item, int) else FlagType.FLOAT,
                            source="json_config"
                        )
                        result.add_flag(flag)
                    elif isinstance(item, str):
                        try:
                            flag = ParsedFlag(
                                name=_normalize_name(f"{prefix}array"),
                                value=float(item),
                                type_=FlagType.FLOAT,
                                source="json_config"
                            )
                            result.add_flag(flag)
                        except ValueError:
                            pass
        
        extract_flags(obj)
        
    except json.JSONDecodeError as e:
        result.errors.append(f"JSON decode error: {e}")
    
    return result


def _parse_ini_toml(data: bytes) -> ParseResult:
    """Parse INI or TOML configuration data."""
    result = ParseResult(flags=[])
    
    try:
        # Try to detect format by looking for section headers
        text = data.decode('utf-8', errors='replace').strip()
        
        if not text.startswith(('[', '#')) and '=' in text:
            # Likely INI format
            lines = text.split('\n')
            
            current_section = ""
            for line in lines:
                line = line.strip()
                
                # Section header
                if line.startswith('[') and line.endswith(']'):
                    section_name = line[1:-1].strip()
                    current_section = f"{section_name}_"
                    continue
                
                # Key-value pair
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')
                    
                    new_key = f"{current_section}{key}" if current_section else key
                    
                    # Type detection and parsing
                    try:
                        if '.' in value:
                            flag = ParsedFlag(
                                name=_normalize_name(new_key),
                                value=float(value),
                                type_=FlagType.FLOAT,
                                source="ini_toml"
                            )
                            result.add_flag(flag)
                        elif value.lower() in ('true', 'false'):
                            flag = ParsedFlag(
                                name=_normalize_name(new_key),
                                value=value.lower(),
                                type_=FlagType.BOOLEAN,
                                source="ini_toml"
                            )
                            result.add_flag(flag)
                        else:
                            # Try integer first
                            try:
                                flag = ParsedFlag(
                                    name=_normalize_name(new_key),
                                    value=int(value),
                                    type_=FlagType.INTEGER,
                                    source="ini_toml"
                                )
                                result.add_flag(flag)
                            except ValueError:
                                # Default to string
                                flag = ParsedFlag(
                                    name=_normalize_name(new_key),
                                    value=value,
                                    type_=FlagType.STRING,
                                    source="ini_toml"
                                )
                                result.add_flag(flag)
                    except Exception:
                        pass
                        
    except UnicodeDecodeError as e:
        result.errors.append(f"INI/TOML decode error: {e}")
    
    return result


def _parse_xml_config(data: bytes) -> ParseResult:
    """Parse XML configuration data."""
    result = ParseResult(flags=[])
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        # Simple regex-based extraction for common patterns
        # Look for attribute-like structures
        attr_pattern = re.compile(r'(\w+)\s*=\s*["\']([^"\']*)["\']|(\w+)\s*=\s*(\d+\.?\d*)', re.IGNORECASE)
        
        matches = list(attr_pattern.finditer(text))
        
        for match in matches:
            if len(match.groups()) == 2:
                # Attribute format: name="value"
                key, value = match.group(1), match.group(2)
                
                try:
                    if '.' in value:
                        flag = ParsedFlag(
                            name=_normalize_name(key),
                            value=float(value),
                            type_=FlagType.FLOAT,
                            source="xml_config"
                        )
                        result.add_flag(flag)
                    elif value.lower() in ('true', 'false'):
                        flag = ParsedFlag(
                            name=_normalize_name(key),
                            value=value.lower(),
                            type_=FlagType.BOOLEAN,
                            source="xml_config"
                        )
                        result.add_flag(flag)
                    else:
                        try:
                            flag = ParsedFlag(
                                name=_normalize_name(key),
                                value=int(value),
                                type_=FlagType.INTEGER,
                                source="xml_config"
                            )
                            result.add_flag(flag)
                        except ValueError:
                            flag = ParsedFlag(
                                name=_normalize_name(key),
                                value=value,
                                type_=FlagType.STRING,
                                source="xml_config"
                            )
                            result.add_flag(flag)
                except Exception:
                    pass
                    
    except UnicodeDecodeError as e:
        result.errors.append(f"XML decode error: {e}")
    
    return result


def _parse_hex_dump(data: bytes) -> ParseResult:
    """Parse hex dump for string patterns."""
    result = ParseResult(flags=[])
    
    try:
        text = data.decode('utf-8', errors='replace')
        
        # Look for common hex dump prefixes and extract strings
        lines = text.split('\n')
        
        for line in lines:
            # Skip header lines (usually contain "0x", "offset:", etc.)
            if any(h in line.lower() for h in ['0x', 'offset:', 'addr:', 'location']):
                continue
            
            # Extract printable strings from hex data
            # Pattern matches sequences of printable characters
            string_pattern = re.compile(r'([0-9a-fA-F]{2,4}\s+)*\s*("([^"]*)"|\'([^\']*)\'|\S{1,32})')
            
            for match in string_pattern.finditer(line):
                # Try to extract the actual string content
                groups = match.groups()
                
                if len(groups) >= 4:
                    # Group 4 is the quoted string
                    value = groups[3]
                    name = _normalize_name(f"hex_string_{len(result.flags)}")
                    
                    flag = ParsedFlag(
                        name=name,
                        value=value.strip('"\''),
                        type_=FlagType.STRING,
                        source="hex_dump"
                    )
                    result.add_flag(flag)
                
    except Exception:
        pass
    
    return result


def _auto_detect_format(data: bytes) -> Tuple[str, Optional[bytes]]:
    """Auto-detect the configuration format from binary data."""
    try:
        text = data.decode('utf-8', errors='replace')
        
        # Check for JSON (most common in modern firmware)
        if text.strip().startswith(('{', '[')) and '{' in text:
            return "json", data
        
        # Check for INI/TOML
        if any(text.startswith(x) or x in text[:200] for x in ('[Section', '# ', 'key =')):
            return "ini_toml", data
        
        # Check for XML
        if text.strip().startswith(('<') and '>' in text:
            xml_depth = 0
            for char in text[:500]:
                if char == '<':
                    xml_depth += 1
                elif char == '>':
                    xml_depth -= 1
                    if xml_depth <= 0:
                        return "xml", data
            
        # Check for hex dump patterns
        if any(x in text.lower() for x in ('0x', 'offset:', 'addr:', 'location:', 'hex')):
            return "hex_dump", data
        
        # Default to binary blob search
        return "binary_blob", None
    
    except UnicodeDecodeError:
        return "binary_blob", None


def parse_config(data: Union[bytes, BinaryIO, str, Path], 
                 format_hint: Optional[str] = None) -> ParseResult:
    """
    Main entry point for parsing configuration from various sources.
    
    Args:
        data: Bytes, file-like object, string path, or Path object
        format_hint: Optional hint to force a specific parser (json, ini_toml, xml, hex_dump)
    
    Returns:
        ParseResult containing all parsed flags and metadata
    """
    result = ParseResult(flags=[])
    
    # Normalize input
    if isinstance(data, str):
        path = Path(data)
        if not path.exists():
            result.errors.append(f"Path does not exist: {data}")
            return result
        
        try:
            data = path.read_bytes()
        except Exception as e:
            result.errors.append(f"Failed to read file: {e}")
            return result
    
    elif isinstance(data, BinaryIO):
        # Read from file-like object
        try:
            data.seek(0)
            content = data.read()
        except Exception as e:
            result.errors.append(f"Failed to read stream: {e}")
            return result
        
        if not content:
            result.warnings.append("Empty input")
            return result
    
    elif isinstance(data, bytes):
        pass  # Already bytes
    
    else:
        result.errors.append(f"Unsupported type: {type(data)}")
        return result
    
    # Auto-detect format or use hint
    if format_hint:
        detected = format_hint
    else:
        detected, _ = _auto_detect_format(content)
    
    # Select parser based on detection
    parsers = {
        "json": _parse_json_config,
        "ini_toml": _parse_ini_toml,
        "xml": _parse_xml_config,
        "hex_dump": _parse_hex_dump,
        "binary_blob": _parse_binary_blob,
    }
    
    parser = parsers.get(detected, _