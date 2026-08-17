package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Firmware Binary Diff Tool for fwxray.
 * Compares two firmware images and surfaces: new binaries, flipped config flags,
 * added certs, and shifted entropy regions.
 */
public class binary_diff {

    // --- Configuration Constants ---
    private static final int ELF_MAGIC = 0x464C457F;       // "ELF\0" (little-endian)
    private static final int PE_MAGIC = 0x0100;             // PE32 header signature
    private static final int FAT_MAGIC = 0x46415421;        // FAT32 magic
    private static final int CONFIG_SECTION_SIZE = 8192;    // Typical config section size

    // --- Main Entry Point (Runnable Demo) ---
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Usage: java binary_diff <image1> <image2>");
            System.exit(0);
        }

        Path img1 = Paths.get(args[0]);
        Path img2 = Paths.get(args[1]);

        if (!Files.exists(img1)) {
            throw new FileNotFoundException("Image 1 not found: " + img1);
        }
        if (!Files.exists(img2)) {
            throw new FileNotFoundException("Image 2 not found: " + img2);
        }

        System.out.println("=== fwxray Binary Diff ===");
        System.out.println("Image 1: " + img1.toAbsolutePath());
        System.out.println("Image 2: " + img2.toAbsolutePath());
        System.out.println();

        // Step 1: Load and parse both images
        FirmwareImage imgA = new FirmwareImage(img1);
        FirmwareImage imgB = new FirmwareImage(img2);

        // Step 2: Compute high-level diffs
        DiffReport report = computeDiff(imgA, imgB);

        // Step 3: Print results
        printReport(report);
    }

    // --- Core Diff Logic ---
    private static DiffReport computeDiff(FirmwareImage a, FirmwareImage b) {
        DiffReport r = new DiffReport();

        // 1. New binaries (files present in B but not A)
        Set<String> filesA = new HashSet<>(a.files.keySet());
        Set<String> filesB = new HashSet<>(b.files.keySet());
        
        for (String f : filesB) {
            if (!filesA.contains(f)) {
                r.newBinaries.add(f);
            }
        }

        // 2. Flipped config flags
        r.configFlags = compareConfig(a, b);

        // 3. Added certificates
        r.certsAdded = findCertDifferences(a, b);

        // 4. Shifted entropy regions
        r.entropyShifts = analyzeEntropyShifts(a, b);

        return r;
    }

    // --- FirmwareImage: Container for parsed image data ---
    static class FirmwareImage {
        Path path;
        long size;
        String magic;
        int headerType;
        Map<String, byte[]> sections = new LinkedHashMap<>();
        Set<String> files = new HashSet<>();

        FirmwareImage(Path p) throws IOException {
            this.path = p;
            this.size = Files.readAllBytes(p).length;
            
            // Detect magic and parse header
            byte[] header = Files.readAllBytes(Files.probeDirectory(p));
            if (header.length < 4) return;

            int m = Integer.reverseBytes(header[0] | header[1] << 8 | 
                                          header[2] << 16 | header[3] << 24);
            
            this.magic = new String(header, 0, 4);
            this.headerType = m;

            // Parse sections based on magic
            parseSections(header);
        }

        private void parseSections(byte[] header) {
            if (header.length < 64) return;

            switch (this.magic) {
                case "ELF":
                    parseElfSections(header);
                    break;
                case "PE32\0":
                    parsePeSections(header);
                    break;
                default:
                    // Generic section parsing for unknown formats
                    extractGenericSections(header);
            }
        }

        private void parseElfSections(byte[] header) {
            if (header.length < 64) return;
            
            int e_shoff = Integer.reverseBytes(header[0x2A]);
            int e_shentsize = Integer.reverseBytes(header[0x38]);
            int e_shnum = Integer.reverseBytes(header[0x39]);

            for (int i = 0; i < e_shnum && i * e_shentsize + 64 < header.length; i++) {
                int sh_offset = Integer.reverseBytes(header[0x2A + i * e_shentsize + 0x18]);
                if (sh_offset > 0) {
                    sections.put("elf_section_" + i, 
                        Arrays.copyOfRange(header, sh_offset, Math.min(sh_offset + 64, header.length)));
                }
            }
        }

        private void parsePeSections(byte[] header) {
            if (header.length < 128) return;
            
            int peOffset = Integer.reverseBytes(header[0x3C]);
            if (peOffset > 0 && peOffset + 64 < header.length) {
                sections.put("pe_section_0", 
                    Arrays.copyOfRange(header, peOffset, Math.min(peOffset + 64, header.length)));
            }
        }

        private void extractGenericSections(byte[] header) {
            // Look for common section markers in the binary
            String text = new String(header);
            
            if (text.contains(".text") || text.contains(".data")) {
                sections.put("generic_sections", Arrays.copyOfRange(header, 0, Math.min(128, header.length)));
            }

            // Extract any embedded files or archives
            extractEmbeddedFiles(header);
        }

        private void extractEmbeddedFiles(byte[] header) {
            // Look for ZIP/PEM signatures indicating embedded content
            int zipSig = Integer.reverseBytes(header[0] | header[1] << 8 | 
                                             header[2] << 16 | header[3] << 24);
            
            if (zipSig == 0x504B0304) { // ZIP local file header
                sections.put("embedded_zip", Arrays.copyOfRange(header, 0, Math.min(256, header.length)));
            }
        }
    }

    // --- DiffReport: Container for all differences found ---
    static class DiffReport {
        List<String> newBinaries = new ArrayList<>();
        Map<String, String> configFlags = new LinkedHashMap<>();
        List<CertDiff> certsAdded = new ArrayList<>();
        List<EntropyShift> entropyShifts = new ArrayList<>();

        public void print() {
            System.out.println("--- New Binaries ---");
            if (newBinaries.isEmpty()) {
                System.out.println("  None detected.");
            } else {
                for (String f : newBinaries) {
                    System.out.println("  + " + f);
                }
            }

            System.out.println("\n--- Config Flags ---");
            if (configFlags.isEmpty()) {
                System.out.println("  No flag changes detected.");
            } else {
                for (Map.Entry<String, String> e : configFlags.entrySet()) {
                    System.out.println("  ~ " + e.getKey() + " = " + e.getValue());
                }
            }

            System.out.println("\n--- Certificates ---");
            if (certsAdded.isEmpty()) {
                System.out.println("  No new certificates detected.");
            } else {
                for (CertDiff c : certsAdded) {
                    System.out.println("  + " + c.subject + " (" + c.fingerprint.substring(0,8) + "...") ;
                }
            }

            System.out.println("\n--- Entropy Shifts ---");
            if (entropyShifts.isEmpty()) {
                System.out.println("  No entropy region shifts detected.");
            } else {
                for (EntropyShift s : entropyShifts) {
                    System.out.println("  >> " + s.from + " -> " + s.to);
                }
            }
        }
    }

    // --- Config Flag Comparison ---
    private static Map<String, String> compareConfig(FirmwareImage a, FirmwareImage b) {
        Map<String, String> changes = new LinkedHashMap<>();

        // Look for common config formats in sections
        byte[] dataA = extractConfigData(a);
        byte[] dataB = extractConfigData(b);

        if (dataA != null && dataB != null) {
            try {
                // Try JSON parsing first
                String jsonA = new String(dataA, "UTF-8");
                String jsonB = new String(dataB, "UTF-8");

                if (jsonA.trim().startsWith("{") || jsonB.trim().startsWith("{")) {
                    changes = parseJsonConfigDiffs(jsonA, jsonB);
                } else {
                    // Binary blob comparison for config sections
                    changes = compareBinaryConfigs(dataA, dataB);
                }
            } catch (Exception e) {
                // Fallback: simple XOR diff for binary blobs
                changes = compareBinaryConfigs(dataA, dataB);
            }
        }

        return changes;
    }

    private static byte[] extractConfigData(FirmwareImage img) {
        if (img.sections.isEmpty()) return null;

        // Look for config-like sections (typically contain "config", "cfg", etc.)
        for (byte[] section : img.sections.values()) {
            try {
                String text = new String(section);
                if (text.toLowerCase().contains("config") || 
                    text.toLowerCase().contains("cfg")) {
                    return section;
                }
            } catch (Exception e) {}
        }

        // Fallback: first 4KB of image
        return img.size > 0 ? Arrays.copyOfRange(Files.readAllBytes(img.path), 0, Math.min(4096, (int)Math.min(img.size, 4096))) : null;
    }

    private static Map<String, String> parseJsonConfigDiffs(String jsonA, String jsonB) {
        Map<String, String> changes = new LinkedHashMap<>();

        try {
            // Simple JSON diff (no external library)
            String[] linesA = jsonA.split("\n");
            String[] linesB = jsonB.split("\n");

            for (int i = 0; i < Math.max(linesA.length, linesB.length); i++) {
                String lineA = linesA[i].trim();
                String lineB = linesB[i].trim();

                if (!lineA.equals(lineB)) {
                    // Detect flag changes
                    if (lineA.contains("true") && !lineB.contains("true")) {
                        changes.put("flag_" + i, "false");
                    } else if (!lineA.contains("true") && lineB.contains("true")) {
                        changes.put("flag_" + i, "true");
                    }
                }
            }
        } catch (Exception e) {}

        return changes;
    }

    private static Map<String, String> compareBinaryConfigs(byte[] a, byte[] b) {
        Map<String, String> changes = new LinkedHashMap<>();

        if (a == null || b == null) return changes;

        // Simple XOR-based diff for binary config blobs
        int minLen = Math.min(a.length, b.length);
        
        for (int i = 0; i < minLen; i++) {
            if ((a[i] ^ b[i]) != 0) {
                // Check if this looks like a boolean flag change
                if (i % 8 == 0 && 
                    (a[i] & 0x01) == 0 && (b[i] & 0x01) != 0) {
                    changes.put("bit_" + i, "flipped");
                }
            }
        }

        return changes;
    }

    // --- Certificate Difference Detection ---
    private static List<CertDiff> findCertDifferences(FirmwareImage a, FirmwareImage b) {
        List<CertDiff> added = new ArrayList<>();

        byte[] dataA = extractConfigData(a);
        byte[] dataB = extractConfigData(b);

        if (dataA == null || dataB == null) return added;

        try {
            // Look for X.509 certificate headers
            int pemStart = findPemHeader(dataA, 1024);
            
            if (pemStart >= 0) {
                // Extract and parse certificates from both images
                List<CertInfo> certsA = extractCerts(dataA, pemStart);
                List<CertInfo> certsB = extractCerts(dataB, pemStart);

                for (CertInfo c : certsB) {
                    boolean foundInA = false;
                    for (CertInfo ca : certsA) {
                        if (ca.fingerprint.equals(c.fingerprint)) {
                            foundInA = true;
                            break;
                        }
                    }
                    
                    if (!foundInA) {
                        added.add(new CertDiff(
                            c.subject, 
                            c.issuer, 
                            c.fingerprint, 
                            "new"
                        ));
                    }
                }
            }
        } catch (Exception e) {}

        return added;
    }

    private static int findPemHeader(byte[] data, int maxLen) {
        // Look for PEM header markers
        String pemStart = new String(data).indexOf("-----BEGIN CERTIFICATE-----");
        
        if (pemStart >= 0 && pemStart < maxLen) {
            return pemStart;
        }

        // Also check for DER-encoded certificates
        int derSig = Integer.reverseBytes(data[0] | data[1] << 8 | 
                                         data[2] << 16 | data[3] << 24);
        
        if (derSig == 0x3082 || derSig == 0x3081) { // ASN.1 SEQUENCE length prefix
            return 0;
        }

        return -1;
    }

    private static List<CertInfo> extractCerts(byte[] data, int offset) throws Exception {
        List<CertInfo> certs = new ArrayList<>();

        String pemStartMarker = "-----BEGIN CERTIFICATE-----";
        int pos = 0;

        while (pos < data.length - pemStartMarker.length()) {
            int idx = new String(data).indexOf(pemStartMarker, pos);
            
            if (idx == -1) break;

            // Extract certificate content between markers
            int endIdx = new String(data).indexOf("-----END CERTIFICATE-----", idx);
            
            if (endIdx > 0) {
                byte[] certData = Arrays.copyOfRange(data, idx + pemStartMarker.length(), 
                                                      endIdx - idx - pemStartMarker.length());

                // Compute fingerprint for quick comparison
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(certData);
                
                certs.add(new CertInfo(
                    new String(hash).substring(0, 8),
                    "Unknown",
                    new String(hash)
                ));

                pos = endIdx + pemStartMarker.length();
            } else {
                break;
            }
        }

        return certs;
    }

    // --- Entropy Region Shift Analysis ---
    private static List<EntropyShift> analyzeEntropyShifts(FirmwareImage a, FirmwareImage b) {
        List<EntropyShift> shifts = new ArrayList<>();

        byte[] dataA = extractConfigData(a);
        byte[] dataB = extractConfigData(b);

        if (dataA == null || dataB == null) return shifts;

        // Calculate entropy for both images
        double entA = calculateEntropy(dataA);
        double entB = calculateEntropy(dataB);

        // Look for regions with significant entropy changes
        int windowSize = 256;
        
        if (dataA.length >= windowSize * 4 && dataB.length >= windowSize * 4) {
            for (int i = 0; i < Math.min(dataA.length, dataB.length) - windowSize * 3; i += windowSize) {
                byte[] chunkA = Arrays.copyOfRange(dataA, i, i + windowSize);
                byte[] chunkB = Arrays.copyOfRange(dataB, i, i + windowSize);

                double entChunkA = calculateEntropy(chunkA);
                double entChunkB = calculateEntropy(chunkB);

                // Detect significant entropy shift (> 2.0 bits difference)