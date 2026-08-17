use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::time::SystemTime;

/// Magic number for valid config header
const CONFIG_MAGIC: u32 = 0xFWXRAY1;
const CONFIG_VERSION: u8 = 2;

#[derive(Debug, Clone)]
pub struct ConfigHeader {
    pub magic: u32,
    pub version: u8,
    pub checksum: u32,
    pub timestamp: SystemTime,
}

impl ConfigHeader {
    pub fn validate(&self) -> Result<(), String> {
        if self.magic != CONFIG_MAGIC {
            return Err(format!("Invalid magic number: 0x{:08X}", self.magic));
        }
        if self.version != CONFIG_VERSION {
            return Err(format!(
                "Unsupported version: {}. Expected {}",
                self.version, CONFIG_VERSION
            ));
        }
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> Result<Self, String> {
        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf).map_err(|e| format!("Read error: {}", e))?;
        let magic = u32::from_le_bytes(magic_buf);

        if magic != CONFIG_MAGIC {
            return Err(format!(
                "Expected magic 0x{:08X}, got 0x{:08X}",
                CONFIG_MAGIC, magic
            ));
        }

        let version = reader.read_u8().map_err(|e| format!("Read error: {}", e))?;
        let checksum = u32::from_le_bytes([
            reader.read_u8().unwrap_or(0),
            reader.read_u8().unwrap_or(0),
            reader.read_u8().unwrap_or(0),
            reader.read_u8().unwrap_or(0),
        ]);

        let now = SystemTime::now();
        Ok(ConfigHeader {
            magic,
            version,
            checksum,
            timestamp: now,
        })
    }
}

#[derive(Debug, Clone)]
pub enum FlagType {
    Bool,
    U8(u8),
    U16(u16),
    U32(u32),
    String(String),
    Bitmask(Vec<u8>),
}

impl fmt::Display for FlagType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlagType::Bool => write!(f, "bool"),
            FlagType::U8(v) => write!(f, "u8({})", v),
            FlagType::U16(v) => write!(f, "u16({})", v),
            FlagType::U32(v) => write!(f, "u32({})", v),
            FlagType::String(s) => write!(f, "string(\"{}\")", s.trim()),
            FlagType::Bitmask(_) => write!(f, "bitmask"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlagField {
    pub name: String,
    pub offset: u64,
    pub size: u32,
    pub r#type: FlagType,
    pub description: Option<String>,
}

impl fmt::Display for FlagField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (offset=0x{:X}, size={} bytes)", self.name, self.offset, self.size)?;
        if let Some(desc) = &self.description {
            writeln!(f, " // {}", desc)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum FlagChange {
    Added(FlagField),
    Removed(String),
    Modified {
        field: String,
        old_value: FlagType,
        new_value: FlagType,
    },
    Unchanged(String),
}

impl fmt::Display for FlagChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlagChange::Added(field) => write!(f, "+ {}", field),
            FlagChange::Removed(name) => write!(f, "- {}", name),
            FlagChange::Modified { field, old_value, new_value } => {
                write!(
                    f,
                    "~ {} : {} -> {}",
                    field, old_value, new_value
                )
            }
            FlagChange::Unchanged(name) => write!(f, "= {}", name),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigDiff {
    pub header: ConfigHeader,
    pub changes: Vec<FlagChange>,
    pub summary: SummaryStats,
}

impl ConfigDiff {
    pub fn new(header: ConfigHeader) -> Self {
        ConfigDiff {
            header,
            changes: Vec::new(),
            summary: SummaryStats::default(),
        }
    }

    pub fn record_change(&mut self, change: FlagChange) {
        match &change {
            FlagChange::Added(_) => self.summary.added += 1,
            FlagChange::Removed(_) => self.summary.removed += 1,
            FlagChange::Modified { .. } => self.summary.modified += 1,
            FlagChange::Unchanged(_) => {}
        }
        self.changes.push(change);
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn has_changes(&self) -> bool {
        !self.changes.iter().any(|c| matches!(c, FlagChange::Unchanged(_)))
    }

    pub fn print_summary(&self) {
        println!("\n=== Config Diff Summary ===");
        println!("Total changes: {}", self.summary.total());
        println!("  Added:   {}", self.summary.added);
        println!("  Removed: {}", self.summary.removed);
        println!("  Modified:{}", self.summary.modified);
    }

    pub fn print_changes(&self) {
        if self.changes.is_empty() {
            println!("\nNo changes detected.");
            return;
        }

        println!("\n=== Detailed Changes ===");
        for change in &self.changes {
            println!("{}", change);
        }
    }
}

#[derive(Debug, Default)]
pub struct SummaryStats {
    pub added: u32,
    pub removed: u32,
    pub modified: u32,
}

impl SummaryStats {
    pub fn total(&self) -> u32 {
        self.added + self.removed + self.modified
    }
}

/// In-memory representation of a parsed config file.
#[derive(Debug, Default)]
pub struct ConfigStore {
    pub header: ConfigHeader,
    pub fields: HashMap<String, FlagField>,
    pub values: HashMap<String, FlagType>,
}

impl ConfigStore {
    pub fn new() -> Self {
        let now = SystemTime::now();
        ConfigStore {
            header: ConfigHeader {
                magic: CONFIG_MAGIC,
                version: CONFIG_VERSION,
                checksum: 0,
                timestamp: now,
            },
            fields: HashMap::new(),
            values: HashMap::new(),
        }
    }

    pub fn insert_field(&mut self, field: FlagField) {
        let name = &field.name;
        if !self.fields.contains_key(name) {
            self.fields.insert(name.clone(), field);
        }
    }

    pub fn get_field_mut(&mut self, name: &str) -> Option<&mut FlagType> {
        self.values.get_mut(name)
    }

    pub fn set_value(&mut self, name: &str, value: FlagType) {
        if let Some(field) = self.fields.get(name) {
            // Update field type info if needed
            if !matches!(&field.r#type, FlagType::String(_)) && !matches!(&value, FlagType::String(_)) {
                self.fields.insert(name.to_string(), field.clone());
            }
        }
        self.values.insert(name.to_string(), value);
    }

    pub fn get_value(&self, name: &str) -> Option<&FlagType> {
        self.values.get(name)
    }

    pub fn diff_with(&self, other: &ConfigStore) -> ConfigDiff {
        let mut diff = ConfigDiff::new(self.header.clone());
        
        // Check for new/removed fields
        let added_fields: HashSet<String> = 
            self.fields.keys().filter(|k| !other.fields.contains_key(*k)).cloned();
        let removed_fields: HashSet<String> = 
            other.fields.keys().filter(|k| !self.fields.contains_key(*k)).cloned();

        for name in &added_fields {
            if let Some(field) = self.fields.get(name) {
                diff.record_change(FlagChange::Added(field.clone()));
            }
        }

        for name in &removed_fields {
            diff.record_change(FlagChange::Removed(name.clone()));
        }

        // Check modified values
        for (name, value) in &self.values {
            if let Some(other_value) = other.values.get(name) {
                if !values_equal(value, other_value) {
                    diff.record_change(FlagChange::Modified {
                        field: name.clone(),
                        old_value: other_value.clone(),
                        new_value: value.clone(),
                    });
                } else {
                    diff.record_change(FlagChange::Unchanged(name.clone()));
                }
            }
        }

        // Check for removed values (fields that existed but now have no value)
        for name in &removed_fields {
            if let Some(field) = self.fields.get(name) {
                if !matches!(&field.r#type, FlagType::String(_)) {
                    diff.record_change(FlagChange::Removed(name.clone()));
                }
            }
        }

        // Sort changes for consistent output
        diff.changes.sort_by(|a, b| a.to_string().cmp(&b.to_string()));

        diff
    }
}

/// Compare two FlagType values for equality.
fn values_equal(a: &FlagType, b: &FlagType) -> bool {
    match (a, b) {
        (FlagType::Bool, FlagType::Bool) => a == b,
        (FlagType::U8(a), FlagType::U8(b)) => a == b,
        (FlagType::U16(a), FlagType::U16(b)) => a == b,
        (FlagType::U32(a), FlagType::U32(b)) => a == b,
        (FlagType::String(a), FlagType::String(b)) => a == b,
        (FlagType::Bitmask(a), FlagType::Bitmask(b)) => a == b,
    }
}

/// Parse a binary config file and return the parsed store.
pub fn parse_config<R: Read>(reader: R) -> Result<ConfigStore, String> {
    let header = ConfigHeader::read(reader)?;
    
    // For demonstration, we'll create a minimal field set
    // In production this would read from actual binary structure
    
    Ok(ConfigStore {
        header,
        fields: HashMap::new(), // Would be populated from header
        values: HashMap::new(), // Would be populated from file content
    })
}

/// Write a config store to a binary writer.
pub fn write_config<W: Write>(writer: W, store: &ConfigStore) -> Result<(), String> {
    let mut buf = [0u8; 16];
    
    // Write header
    buf[0..4].copy_from_slice(&store.header.magic.to_le_bytes());
    buf[4] = store.header.version;
    buf[5..9].copy_from_slice(&store.header.checksum.to_le_bytes());
    
    writer.write_all(&buf).map_err(|e| format!("Write error: {}", e))?;

    Ok(())
}

/// Demo function showing the complete workflow.
pub fn main_demo() -> Result<(), String> {
    println!("fwxray::config_flag_parser - Demo");
    println!("=================================");

    // Create two config stores with different values
    let mut store1 = ConfigStore::new();
    store1.values.insert("debug".to_string(), FlagType::Bool(true));
    store1.values.insert("version".to_string(), FlagType::U32(1));
    store1.values.insert("feature_x".to_string(), FlagType::String("enabled".to_string()));

    let mut store2 = ConfigStore::new();
    store2.values.insert("debug".to_string(), FlagType::Bool(false)); // Changed!
    store2.values.insert("version".to_string(), FlagType::U32(1));   // Same
    store2.values.insert("feature_x".to_string(), FlagType::String("disabled".to_string())); // Changed!
    store2.values.insert("new_feature".to_string(), FlagType::Bool(true)); // Added!

    // Compute diff
    let diff = store1.diff_with(&store2);

    // Print results
    println!("Header: {:?}", diff.header);
    diff.print_summary();
    diff.print_changes();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_validation() {
        let header = ConfigHeader {
            magic: CONFIG_MAGIC,
            version: CONFIG_VERSION,
            checksum: 0x12345678,
            timestamp: SystemTime::now(),
        };
        
        assert!(header.validate().is_ok());

        let bad_magic = ConfigHeader {
            magic: CONFIG_MAGIC + 1,
            version: CONFIG_VERSION,
            checksum: 0x12345678,
            timestamp: SystemTime::now(),
        };
        
        assert!(bad_magic.validate().is_err());
    }

    #[test]
    fn test_value_equality() {
        let bool_true = FlagType::Bool(true);
        let bool_false = FlagType::Bool(false);
        
        assert!(values_equal(&bool_true, &bool_true));
        assert!(!values_equal(&bool_true, &bool_false));

        let u32_a = FlagType::U32(42);
        let u32_b = FlagType::U32(42);
        
        assert!(values_equal(&u32_a, &u32_b));
    }

    #[test]
    fn test_diff_detection() {
        let mut s1 = ConfigStore::new();
        s1.values.insert("x".to_string(), FlagType::Bool(true));

        let mut s2 = ConfigStore::new();
        s2.values.insert("y".to_string(), FlagType::Bool(false));

        let diff = s1.diff_with(&s2);
        
        assert!(!diff.is_empty());
        assert!(diff.has_changes());
    }
}

fn main() {
    if let Err(e) = main_demo() {
        eprintln!("Demo error: {}", e);
        std::process::exit(1);
    }
}