use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::io::{self, Read};
use sha2::{Sha256, Digest};

/// Represents a detected binary file type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryType {
    Unknown,
    Elf32,
    Elf64,
    Pe32,
    Pe64,
    Fat,
}

impl Default for BinaryType {
    fn default() -> Self {
        BinaryType::Unknown
    }
}

/// Metadata extracted from a firmware image
#[derive(Debug)]
pub struct FirmwareImage {
    pub path: Option<PathBuf>,
    pub data: Vec<u8>,
    pub binary_type: BinaryType,
    pub checksum: String,
    pub entropy: f64,
    pub config_regions: Vec<ConfigRegion>,
}

/// A region in the firmware that may contain configuration flags
#[derive(Debug)]
pub struct ConfigRegion {
    pub offset: u64,
    pub size: usize,
    pub name: String,
}

impl Default for FirmwareImage {
    fn default() -> Self {
        FirmwareImage {
            path: None,
            data: Vec::new(),
            binary_type: BinaryType::Unknown,
            checksum: "0".to_string(),
            entropy: 0.0,
            config_regions: vec![],
        }
    }
}

/// Result of comparing two firmware images
#[derive(Debug)]
pub struct DiffResult {
    pub new_binaries: Vec<BinaryDiff>,
    pub modified_binaries: Vec<ModifiedRegion>,
    pub flipped_flags: Vec<ConfigFlagChange>,
    pub added_certs: Vec<CertInfo>,
    pub shifted_entropy: Vec<EntropyShift>,
}

/// Information about a newly detected binary
#[derive(Debug)]
pub struct BinaryDiff {
    pub path: String,
    pub offset: u64,
    pub size: usize,
    pub new_type: BinaryType,
    pub old_type: Option<BinaryType>,
}

/// A region that was modified between images
#[derive(Debug)]
pub struct ModifiedRegion {
    pub offset: u64,
    pub size: usize,
    pub description: String,
}

/// A configuration flag that changed state
#[derive(Debug)]
pub struct ConfigFlagChange {
    pub name: String,
    pub old_value: bool,
    pub new_value: bool,
    pub offset: u64,
}

/// Information about a detected certificate
#[derive(Debug)]
pub struct CertInfo {
    pub offset: u64,
    pub size: usize,
    pub subject: String,
    pub issuer: String,
}

/// A shift in high-entropy regions between images
#[derive(Debug)]
pub struct EntropyShift {
    pub old_offset: Option<u64>,
    pub new_offset: u64,
    pub size: usize,
    pub description: String,
}

/// Magic bytes for common binary types
const MAGIC_BYTES: &[(&[u8], BinaryType)] = &[
    (b"\x7fELF", BinaryType::Elf32),
    (b"\x7f454c46", BinaryType::Elf64), // Little endian ELF 64
    (b"\x4e4c467f", BinaryType::Elf64), // Big endian ELF 64
    (b"MZ", BinaryType::Pe32),
    (b"PE\x00\x00", BinaryType::Pe64),
];

/// Detect the binary type from raw data
pub fn detect_binary_type(data: &[u8]) -> BinaryType {
    if data.len() < 4 {
        return BinaryType::Unknown;
    }

    for (magic, btype) in MAGIC_BYTES.iter().copied() {
        if data[..magic.len()] == magic {
            return *btype;
        }
    }

    // Check for FAT filesystem signatures
    if data.len() >= 512 && data[0x3e] == b'F' && data[0x3f] == b'A' {
        return BinaryType::Fat;
    }

    BinaryType::Unknown
}

/// Calculate Shannon entropy of a byte slice
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in data.iter().take(1024) { // Limit to first 1KB for speed
        freq[b as usize] += 1;
    }

    let total: u32 = freq.iter().sum();
    if total == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let prob = count as f64 / total as f64;
            entropy -= (prob * prob.ln()).max(0.0);
        }
    }

    // Normalize to max of 8.0 for bytes
    entropy / 8.0
}

/// Read a firmware image from disk
pub fn read_firmware(path: &Path) -> io::Result<FirmwareImage> {
    let mut data = Vec::new();
    fs::read(path)?;
    
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Empty firmware image",
        ));
    }

    let binary_type = detect_binary_type(&data);
    let checksum = format!("{:x}", Sha256::digest(&data));
    let entropy = calculate_entropy(&data);

    // Default config regions for common types
    let mut config_regions = Vec::new();
    
    match binary_type {
        BinaryType::Elf32 | BinaryType::Elf64 => {
            // ELF has various headers and sections that might contain config
            if data.len() > 0x100 {
                // Check for .config section or similar
                let mut found_config = false;
                for &section in &[b".config", b"CONFIG", b"CFG"] {
                    if let Ok(offset) = find_section(&data, section) {
                        config_regions.push(ConfigRegion {
                            offset: (offset + 64) as u64, // After header
                            size: (data.len() - 0x100).min(0x1000),
                            name: format!("{} section", std::str::from_utf8(section).unwrap_or("config")),
                        });
                        found_config = true;
                    }
                }
            }
        }
        BinaryType::Pe32 | BinaryType::Pe64 => {
            // PE headers often have resource sections with config
            if data.len() > 0x180 {
                let image_size: u32 = u32::from_le_bytes([data[0x18], data[0x19], data[0x1a], data[0x1b] as u32]);
                if image_size > 0 && (image_size as usize) < data.len() {
                    // Check for common resource config regions
                    let mut found = false;
                    for &res in &[b"RCDATA", b".rsrc", b"CONFIG"] {
                        if let Ok(offset) = find_section(&data, res) {
                            config_regions.push(ConfigRegion {
                                offset: (offset + 64) as u64,
                                size: (data.len() - 0x180).min(0x2000),
                                name: format!("{} resource", std::str::from_utf8(res).unwrap_or("resource")),
                            });
                            found = true;
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(FirmwareImage {
        path: Some(path.to_path_buf()),
        data,
        binary_type,
        checksum,
        entropy,
        config_regions,
    })
}

/// Find a section by name in the image (simplified search)
fn find_section(data: &[u8], name: &[u8]) -> io::Result<usize> {
    let mut offset = 0;
    while offset + name.len() <= data.len() {
        if &data[offset..offset + name.len()] == name {
            return Ok(offset);
        }
        offset += 4; // Skip by 4 bytes
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Section not found: {:?}", std::str::from_utf8(name).unwrap_or("???")),
    ))
}

/// Compare two firmware images and produce a detailed diff report
pub fn compare_binaries(img1: &FirmwareImage, img2: &FirmwareImage) -> DiffResult {
    let mut result = DiffResult::default();

    // 1. Check for new binaries (files present in one but not other)
    // For simple comparison, we check if the overall checksum changed significantly
    if img1.checksum != img2.checksum {
        // Calculate similarity ratio
        let common_bytes: u32 = img1.data.iter()
            .zip(img2.data.iter())
            .filter(|(a, b)| a == b)
            .count();
        
        let total = (img1.data.len() + img2.data.len()).max(1);
        let similarity = common_bytes as f64 / total as f64;

        if similarity < 0.95 {
            // Significant change - likely new binaries or major modifications
            result.new_binaries.push(BinaryDiff {
                path: format!("root (similarity {:.2}%)", similarity * 100),
                offset: 0,
                size: img1.data.len().min(img2.data.len()),
                new_type: img2.binary_type,
                old_type: Some(img1.binary_type),
            });
        }
    }

    // 2. Check config regions for flipped flags
    let all_regions = [
        &img1.config_regions,
        &img2.config_regions,
    ]
    .iter()
    .flatten()
    .collect::<Vec<_>>();

    for region in all_regions {
        if region.name.contains("config") || region.name.contains("CFG") {
            // Compare the config region content
            let offset = (region.offset as usize).min(img1.data.len());
            let size = region.size.min(img1.data.len().saturating_sub(offset));
            
            if img2.data.len() > offset + size {
                let old_data: Vec<u8> = img1.data[offset..offset+size].to_vec();
                let new_data: Vec<u8> = img2.data[offset..offset+size].to_vec();

                // Look for single-bit flips (likely boolean flags)
                if let Some(flag_change) = detect_flag_flip(&old_data, &new_data) {
                    result.flipped_flags.push(ConfigFlagChange {
                        name: format!("{} flag", region.name),
                        old_value: flag_change.old_value,
                        new_value: flag_change.new_value,
                        offset: (region.offset + flag_change.bit_offset) as u64,
                    });
                }
            }
        }
    }

    // 3. Check for added certificates using entropy and magic bytes
    result.added_certs = detect_certificates(&img1.data, &img2.data);

    // 4. Detect shifted entropy regions
    result.shifted_entropy = detect_shifted_entropy(&img1.data, &img2.data);

    // 5. Find modified binary regions (non-trivial changes)
    result.modified_binaries = find_modified_regions(img1, img2);

    result
}

/// Detect flipped boolean flags between two data slices
fn detect_flag_flip(old_data: &[u8], new_data: &[u8]) -> Option<FlagFlip> {
    if old_data.len() != new_data.len() || old_data.is_empty() {
        return None;
    }

    // Look for single-bit differences (likely boolean flags)
    let mut bit_offset = 0;
    
    for (i, (&old_b, &new_b)) in old_data.iter().zip(new_data.iter()).enumerate() {
        if old_b != new_b {
            // This byte changed - check if it's a single-bit flip
            let xor = old_b ^ new_b;
            
            // Single bit flip means only one bit differs
            if xor.count_ones() == 1 {
                let bit_offset_in_byte = (xor.trailing_zeros()) as usize;
                
                // Return the first significant flag change found
                return Some(FlagFlip {
                    byte_offset: i,
                    bit_offset: bit_offset_in_byte,
                    old_value: old_b & (1 << bit_offset_in_byte) != 0,
                    new_value: new_data[i] & (1 << bit_offset_in_byte) != 0,
                });
            }
        }
    }

    None
}

/// Information about a detected flag flip
struct FlagFlip {
    byte_offset: usize,
    bit_offset: u8,
    old_value: bool,
    new_value: bool,
}

/// Detect X.509 certificates in firmware data
fn detect_certificates(old_data: &[u8], new_data: &[u8]) -> Vec<CertInfo> {
    let mut certs = Vec::new();

    // Common certificate magic bytes and sizes
    const CERT_SIZES: &[usize] = &[128, 256, 512, 1024];
    
    for (i, &size) in CERT_SIZES.iter().copied().enumerate() {
        let offset = i * size;
        
        if old_data.len() > offset + size && new_data.len() > offset + size {
            // Check if this region looks like a certificate
            // Certificates typically have high entropy and specific headers
            
            let old_entropy = calculate_entropy(&old_data[offset..offset+size]);
            let new_entropy = calculate_entropy(&new_data[offset..offset+size]);

            // Certificate-like: medium-high entropy, reasonable size
            if (0.5..1.0).contains(&old_entropy) || 
               (0.5..1.0).contains(&new_entropy) {
                
                let is_new = new_entropy > old_entropy && 
                           new_data[offset] == 0x30 && // ASN.1 SEQUENCE tag
                           new_data[offset+1] >= 2;    // Reasonable length

                if is_new || (old_entropy < 0.4) {
                    certs.push(CertInfo {
                        offset: offset as u64,
                        size,
                        subject: format!("Region at 0x{:x}", offset),
                        issuer: "Unknown".to_string(),
                    });
                }
            }
        }
    }

    // Also scan for ASN.1 SEQUENCE headers (common in PEM/DER certs)
    let mut asn1_offset = 0;
    while asn1_offset + 2 <= new_data.len() {
        if new_data[asn1_offset] == 0x30 && new_data[asn1_offset+1] >= 4 {
            // Potential SEQUENCE - check entropy of following bytes
            let chunk = &new_data[asn1_offset..(asn1_offset + 256).min(new_data.len())];
            if calculate_entropy(chunk) > 0.6 && chunk.len() < 1024 {
                certs.push(CertInfo {
                    offset: asn1_offset as u64,
                    size: chunk.len(),
                    subject: format!("ASN.1 at 0x{:x}", asn1_offset),
                    issuer: "Potential Certificate".to_string(),
                });
            }
        }
        asn1_offset += 2;
    }

    certs.dedup();
    certs
}

/// Detect regions where high-entropy content shifted between images
fn detect_shifted_entropy(old_data: &[u8], new_data: &[u8]) -> Vec<EntropyShift> {
    let mut shifts = Vec::new();

    // Find all high-entropy regions in both images
    const HIGH_ENTROPY_THRESHOLD: f64 = 0.7;
    
    fn find_high_entropy_regions(data: &[u8], window: