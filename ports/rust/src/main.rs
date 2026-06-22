// Rust port of the fwxray CORE check: Shannon entropy + magic-signature
// carving over a firmware image. Passive, offline, single binary, zero deps.
use std::{env, fs};

const MAGICS: &[(&[u8], &str)] = &[
    (&[0x1f, 0x8b, 0x08], "gzip"),
    (b"BZh", "bzip2"),
    (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "xz"),
    (&[0x28, 0xb5, 0x2f, 0xfd], "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"hsqs", "squashfs(le)"),
    (b"UBI#", "ubi"),
    (b"ANDROID!", "android_boot"),
    (b"\x7fELF", "elf"),
    (b"-----BEGIN ", "pem"),
];

/// Shannon entropy in bits/byte (0..8). Empty input -> 0.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ent = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    (ent * 10000.0).round() / 10000.0
}

fn find(data: &[u8], sig: &[u8], from: usize) -> Option<usize> {
    if sig.is_empty() || data.len() < sig.len() {
        return None;
    }
    (from..=data.len() - sig.len()).find(|&i| &data[i..i + sig.len()] == sig)
}

/// Carve a firmware image into magic-anchored sections (label, offset).
pub fn carve_sections(data: &[u8]) -> Vec<(String, usize)> {
    let mut hits: Vec<(usize, &str)> = Vec::new();
    for (sig, label) in MAGICS {
        let mut start = 0;
        while let Some(idx) = find(data, sig, start) {
            hits.push((idx, label));
            start = idx + 1;
        }
    }
    hits.sort_by_key(|h| h.0);
    let mut out = Vec::new();
    let mut last: i64 = -256;
    for (off, label) in hits {
        if (off as i64) - last < 256 {
            continue;
        }
        last = off as i64;
        out.push((label.to_string(), off));
    }
    out
}

fn main() {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: fwxray <firmware-image>");
            std::process::exit(2);
        }
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(2);
        }
    };
    let secs = carve_sections(&data);
    let secs_json: Vec<String> = secs
        .iter()
        .map(|(l, o)| format!("{{\"label\":\"{}\",\"offset\":{}}}", l, o))
        .collect();
    println!(
        "{{\"tool\":\"fwxray\",\"path\":\"{}\",\"size\":{},\"entropy\":{},\"sections\":[{}]}}",
        path,
        data.len(),
        shannon_entropy(&data),
        secs_json.join(",")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_uniform_is_zero() {
        assert_eq!(shannon_entropy(&[7, 7, 7, 7]), 0.0);
    }

    #[test]
    fn entropy_two_symbols_is_one() {
        assert!((shannon_entropy(&[0, 1]) - 1.0).abs() < 0.001);
    }

    #[test]
    fn entropy_all_bytes_is_eight() {
        let buf: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&buf) - 8.0).abs() < 0.001);
    }

    #[test]
    fn carve_detects_elf() {
        let mut data = b"\x7fELF".to_vec();
        data.extend(std::iter::repeat(0).take(300));
        let secs = carve_sections(&data);
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].0, "elf");
    }

    #[test]
    fn carve_empty() {
        assert!(carve_sections(&[]).is_empty());
    }

    #[test]
    fn carve_min_spacing() {
        let mut data = vec![0u8; 400];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[10..14].copy_from_slice(b"\x7fELF");
        assert_eq!(carve_sections(&data).len(), 1);
    }
}
