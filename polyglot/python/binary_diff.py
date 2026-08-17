#!/usr/bin/env python3
"""
fwxray - Binary Diff Tool for Firmware Images

Compares two firmware images and surfaces exactly what changed:
- New binaries (checksum mismatches)
- Flipped config flags (config blob diffs)
- Added certs (certificate chain diffs)
- Shifted entropy regions (compression/header changes)
"""

import hashlib
import struct
import sys
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, BinaryIO, Dict, Any
from difflib import SequenceMatcher
from collections import defaultdict


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class SectionDiff:
    """Represents a diffed section within firmware."""
    name: str = ""
    offset: int = 0
    size: int = 0
    old_checksum: str = ""
    new_checksum: str = ""
    status: str = "unchanged"  # unchanged, modified, added, removed
    
    def __str__(self) -> str:
        if self.status == "added":
            return f"+ {self.name or 'unnamed'} ({self.size} bytes)"
        elif self.status == "removed":
            return f"- {self.name or 'unnamed'} ({self.size} bytes)"
        elif self.status == "modified":
            return f"* {self.name or 'unnamed'}: {self.old_checksum[:8]} -> {self.new_checksum[:8]}"
        else:
            return f"  {self.name or 'unnamed'} (unchanged)"


@dataclass 
class CertDiff:
    """Represents a certificate chain diff."""
    cert_type: str = ""
    old_hash: str = ""
    new_hash: str = ""
    status: str = "unchanged"  # unchanged, added, removed
    
    def __str__(self) -> str:
        if self.status == "added":
            return f"+ {self.cert_type or 'unknown cert'} ({len(self.new_hash)} bytes)"
        elif self.status == "removed":
            return f"- {self.cert_type or 'unknown cert'}"
        else:
            return f"  {self.cert_type or 'cert'} (unchanged)"


@dataclass
class ConfigDiff:
    """Represents a config blob diff."""
    key: str = ""
    old_value: bytes = b""
    new_value: bytes = b""
    status: str = "unchanged"  # unchanged, modified
    
    def __str__(self) -> str:
        if self.status == "modified":
            return f"* {self.key}: {len(self.old_value)} -> {len(self.new_value)} bytes"
        else:
            return f"  {self.key} (unchanged)"


# =============================================================================
# Core Diffing Engine
# =============================================================================

class BinaryDiffEngine:
    """Core engine for binary-level firmware comparison."""
    
    def __init__(self, old_path: str, new_path: str):
        self.old_path = Path(old_path)
        self.new_path = Path(new_path)
        
        # Memory-mapped files for efficient access
        self.old_data: Optional[bytes] = None
        self.new_data: Optional[bytes] = None
        
        # Results containers
        self.sections: List[SectionDiff] = []
        self.certs: List[CertDiff] = []
        self.configs: List[ConfigDiff] = []
        
    def load(self) -> Tuple[int, int]:
        """Load both files into memory. Returns (old_size, new_size)."""
        if not self.old_path.exists():
            raise FileNotFoundError(f"Old file not found: {self.old_path}")
        if not self.new_path.exists():
            raise FileNotFoundError(f"New file not found: {new_path}")
        
        with open(self.old_path, 'rb') as f:
            self.old_data = f.read()
            
        with open(self.new_path, 'rb') as f:
            self.new_data = f.read()
            
        return len(self.old_data), len(self.new_data)
    
    def compute_checksum(self, data: bytes, algorithm: str = "sha256") -> str:
        """Compute checksum for a given algorithm."""
        if algorithm == "md5":
            h = hashlib.md5()
        elif algorithm == "sha1":
            h = hashlib.sha1()
        else:  # default sha256
            h = hashlib.sha256()
        
        h.update(data)
        return h.hexdigest().lower()
    
    def compute_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy of byte distribution."""
        if not data:
            return 0.0
            
        # Count byte frequencies
        freq = defaultdict(int)
        for b in data:
            freq[b] += 1
            
        total = len(data)
        entropy = 0.0
        
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * (p.bit_length() + 2)  # -p*log2(p)
                
        return entropy
    
    def find_sections(self, data: bytes) -> List[Tuple[str, int, int]]:
        """
        Heuristically identify firmware sections.
        
        Returns list of (name, offset, size) tuples for known formats.
        """
        sections = []
        
        # ELF header detection
        if len(data) >= 64 and data[:16] == b'\x7fELF':
            elf_class = data[4]
            endian = '<' if data[5] in (1, 2) else '>'
            
            if elf_class == 1:  # 32-bit
                endian_fmt = f'{endian}I'
            else:  # 64-bit  
                endian_fmt = f'{endian}Q'
                
            e_shoff = struct.unpack(endian_fmt, data[0x2C:0x30])[0]
            e_shentsize = struct.unpack(endian_fmt, data[0x38:0x3C])[0]
            e_shnum = struct.unpack(endian_fmt, data[0x40:0x44])[0]
            
            if e_shoff and e_shentsize > 0 and e_shnum > 0:
                for i in range(e_shnum):
                    sh_offset = struct.unpack(endian_fmt, 
                        data[e_shoff + i*e_shentsize:e_shoff + (i+1)*e_shentsize])[0]
                    sh_name = struct.unpack(endian_fmt,
                        data[sh_offset:sh_offset+4])[0]
                    sh_size = struct.unpack(endian_fmt,
                        data[sh_offset+28:sh_offset+32])[0]
                    
                    if sh_name < 65536:
                        name_bytes = data[sh_name:sh_name+16].rstrip(b'\x00')
                        sections.append((name_bytes.decode('utf-8', errors='replace'), 
                                        sh_offset, sh_size))
        else:
            # PE/COFF header detection (Windows executables)
            if len(data) >= 64 and data[:2] == b'MZ':
                pe_offset = struct.unpack('<H', data[0x3C:0x3E])[0]
                
                if pe_offset + 2 < len(data):
                    pe_magic = struct.unpack('<H', data[pe_offset:pe_offset+2])[0]
                    
                    if pe_magic == 0x10B or pe_magic == 0x20B:  # PE32/PE32+
                        pe_offset += 4
                        
                        num_sections = struct.unpack('<I', 
                            data[pe_offset+28:pe_offset+32])[0]
                        
                        for i in range(num_sections):
                            sec_offset = pe_offset + 60 + i*40
                            name_bytes = data[sec_offset:sec_offset+8].rstrip(b'\x00')
                            sections.append((name_bytes.decode('utf-8', errors='replace'),
                                            0, 0))  # Will compute size later
        
        return sections
    
    def diff_sections(self) -> List[SectionDiff]:
        """Compare sections between old and new firmware."""
        old_sections = self.find_sections(self.old_data or b'')
        new_sections = self.find_sections(self.new_data or b'')
        
        # Build lookup maps
        old_map: Dict[Tuple[str, int], SectionDiff] = {}
        for name, offset, size in old_sections:
            key = (name, offset)
            checksum = self.compute_checksum(
                self.old_data[offset:offset+size] if offset + size <= len(self.old_data) else b''
            )
            section = SectionDiff(name=name, offset=offset, size=size, 
                                  old_checksum=checksum, new_checksum=checksum,
                                  status="unchanged")
            old_map[key] = section
            
        # Check for removed sections (in old but not in new at same location)
        for key, section in list(old_map.items()):
            if key[1] >= len(self.new_data):  # Offset beyond new file
                section.status = "removed"
                
        # Check for added sections (in new but not in old at same location)  
        for name, offset, size in new_sections:
            key = (name, offset)
            if key not in old_map and offset < len(self.new_data):
                checksum = self.compute_checksum(
                    self.new_data[offset:offset+size] if offset + size <= len(self.new_data) else b''
                )
                section = SectionDiff(name=name, offset=offset, size=size,
                                      old_checksum="", new_checksum=checksum,
                                      status="added")
                old_map[key] = section
                
        # Check for modified sections (same location, different content)
        for key in list(old_map.keys()):
            if key[1] < len(self.new_data):
                checksum = self.compute_checksum(
                    self.new_data[key[1]:key[1]+key[2]] if key[1] + key[2] <= len(self.new_data) else b''
                )
                
                old_section = old_map[key]
                if old_section.old_checksum != checksum:
                    old_section.status = "modified"
                    old_section.new_checksum = checksum
                    
        self.sections.extend(old_map.values())
        
        # Sort by offset for consistent output
        self.sections.sort(key=lambda s: (s.offset, -len(s.name)))
        return self.sections
    
    def find_certificates(self, data: bytes) -> List[Tuple[str, int, int]]:
        """
        Heuristically locate certificate blobs in firmware.
        
        Searches for common cert patterns and formats.
        """
        certs = []
        
        # Look for X.509 PEM headers (base64 encoded certificates)
        pem_patterns = [
            b'-----BEGIN CERTIFICATE-----',
            b'-----END CERTIFICATE-----',
            b'-----BEGIN TRUSTED CERTIFICATE-----',
            b'-----BEGIN X509 CERTIFICATE-----',
        ]
        
        for pattern in pem_patterns:
            positions = []
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break
                positions.append(idx)
                pos = idx + len(pattern)
            
            # Filter out duplicates and very close matches (likely same cert found twice)
            filtered = []
            for i, p in enumerate(positions):
                if not filtered or p > filtered[-1] + 20:  # At least 20 bytes apart
                    filtered.append(p)
                    
            certs.extend(filtered)
        
        # Look for DER-encoded certificates (raw binary format)
        # Common sizes: 512, 1024, 2048, 4096 bytes
        der_sizes = [512, 1024, 2048, 4096]
        
        for size in der_sizes:
            pos = 0
            while True:
                idx = data.find(b'\x30\x82', pos)  # DER sequence tag
                if idx == -1 or idx + size > len(data):
                    break
                    
                # Check if it looks like a valid certificate (starts with SEQUENCE tag)
                if data[idx:idx+4] == b'\x30\x82' and idx + size <= len(data):
                    certs.append(idx)
                
                pos = idx + 1
        
        return list(set(certs))  # Deduplicate
    
    def diff_certificates(self) -> List[CertDiff]:
        """Compare certificates between old and new firmware."""
        old_certs = self.find_certificates(self.old_data or b'')
        new_certs = self.find_certificates(self.new_data or b'')
        
        # Group certs by size (likely same cert type)
        old_by_size: Dict[int, List[int]] = defaultdict(list)
        new_by_size: Dict[int, List[int]] = defaultdict(list)
        
        for offset in old_certs:
            if offset + 1024 <= len(self.old_data):
                old_by_size[1024].append(offset)
                
        for offset in new_certs:
            if offset + 1024 <= len(self.new_data):
                new_by_size[1024].append(offset)
        
        # Compare certs of same size
        all_offsets = set(old_certs) | set(new_certs)
        
        for offset in sorted(all_offsets):
            cert_type = "DER" if (offset + 512 <= len(self.new_data or b'') and 
                                  self.new_data[offset:offset+4] == b'\x30\x82') else "PEM"
            
            old_offset = offset
            new_offset = offset
            
            # Check if cert exists in both at same location
            if (old_offset < len(self.old_data) and 
                new_offset < len(self.new_data)):
                
                old_hash = self.compute_checksum(
                    self.old_data[old_offset:old_offset+512] if old_offset + 512 <= len(self.old_data) else b''
                )
                new_hash = self.compute_checksum(
                    self.new_data[new_offset:new_offset+512] if new_offset + 512 <= len(self.new_data) else b''
                )
                
                if old_hash == new_hash:
                    cert = CertDiff(cert_type=cert_type, 
                                   old_hash=old_hash[:8], new_hash=new_hash[:8],
                                   status="unchanged")
                else:
                    cert = CertDiff(cert_type=cert_type,
                                   old_hash=old_hash[:8] if old_offset < len(self.old_data) else "",
                                   new_hash=new_hash[:8] if new_offset < len(self.new_data) else "",
                                   status="modified")
            elif offset in old_certs:
                cert = CertDiff(cert_type=cert_type, 
                               old_hash=self.compute_checksum(
                                   self.old_data[offset:offset+512] if offset + 512 <= len(self.old_data) else b''
                               )[:8],
                               new_hash="", status="removed")
            else:
                cert = CertDiff(cert_type=cert_type, 
                               old_hash="",
                               new_hash=self.compute_checksum(
                                   self.new_data[offset:offset+512] if offset + 512 <= len(self.new_data) else b''
                               )[:8],
                               status="added")
                               
            self.certs.append(cert)
            
        return self.certs
    
    def find_config_blobs(self, data: bytes) -> List[Tuple[str, int, int]]:
        """
        Heuristically locate configuration blobs in firmware.
        
        Looks for common config file patterns and sizes.
        """
        configs = []
        
        # Common config file names/paths embedded in firmware
        config_patterns = [
            b'/etc/config',
            b'/data/config', 
            b'/system/config',
            b'config.bin',
            b'settings.dat',
            b'user.cfg',
        ]
        
        for pattern in config_patterns:
            positions = []
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx == -1:
                    break
                positions.append(idx)
                pos = idx + len(pattern)
            
            # Filter duplicates
            filtered = []
            for i, p in enumerate(positions):
                if not filtered or p > filtered[-1] + 50:
                    filtered.append(p)
                    
            configs.extend(filtered)
        
        return list(set(configs))
    
    def diff_configs(self) -> List[ConfigDiff]:
        """Compare configuration blobs between old and new firmware."""
        old_configs = self.find_config_blobs(self.old_data or b'')
        new_configs = self.find_config_blobs(self.new_data or b'')
        
        # Compare configs at same locations
        all_offsets = set(old_configs) | set(new_configs)
        
        for offset in sorted(all_offsets):
            old_offset = offset
            new_offset = offset
            
            if (old_offset < len(self.old_data) and 
                new_offset < len(self.new_data)):
                
                # Compare content
                old_size = min(4096, len(self.old_data) - old_offset)
                new_size = min(4096, len(self.new_data) - new_offset)
                
                if old_size == new_size:
                    old