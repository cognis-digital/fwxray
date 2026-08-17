using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace fwxray.polyglot.csharp
{
    /// <summary>
    /// Represents a detected change between two firmware images.
    /// </summary>
    public sealed class FirmwareChange
    {
        public enum ChangeType
        {
            NewBinary,
            ModifiedBinary,
            RemovedBinary,
            ConfigFlagChanged,
            ConfigFlagAdded,
            ConfigFlagRemoved,
            CertificateAdded,
            CertificateModified,
            EntropyShiftDetected,
            Unknown
        }

        public ChangeType Type { get; set; }
        public string Description { get; set; }
        public long Offset { get; set; }
        public int Size { get; set; }
        public byte[] BeforeValue { get; set; }
        public byte[] AfterValue { get; set; }
        public string HashBefore { get; set; }
        public string HashAfter { get; set; }

        public static FirmwareChange Create(ChangeType type, string description, long offset = -1, int size = 0)
        {
            return new FirmwareChange
            {
                Type = type,
                Description = description,
                Offset = offset,
                Size = size
            };
        }

        public static FirmwareChange Create(ChangeType type, string description, byte[] before, byte[] after, long offset = -1)
        {
            return new FirmwareChange
            {
                Type = type,
                Description = description,
                Offset = offset,
                BeforeValue = before,
                AfterValue = after,
                HashBefore = before?.Length > 0 ? ComputeHash(before) : null,
                HashAfter = after?.Length > 0 ? ComputeHash(after) : null
            };
        }

        public static FirmwareChange Create(ChangeType type, string description, byte[] value, long offset = -1)
        {
            return new FirmwareChange
            {
                Type = type,
                Description = description,
                Offset = offset,
                Size = value?.Length ?? 0,
                BeforeValue = value,
                AfterValue = value,
                HashBefore = ComputeHash(value),
                HashAfter = ComputeHash(value)
            };
        }

        public static string ComputeHash(byte[] data)
        {
            if (data == null || data.Length == 0) return "empty";
            
            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(data);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
        }

        public override string ToString()
        {
            if (BeforeValue != null && AfterValue != null)
            {
                var diffPct = BeforeValue.Length > 0 ? 
                    Math.Round((double)(AfterValue.Count(b => b == 0 || b == 255) / BeforeValue.Length * 100), 1) : 0;
                
                return $"{Type} at offset {Offset:X8}: diff ≈{diffPct:F1}%";
            }

            if (BeforeValue != null && AfterValue == null)
            {
                return $"Removed: {Type} at offset {Offset:X8}, size {Size} bytes, hash={HashBefore}";
            }

            if (AfterValue != null && BeforeValue == null)
            {
                return $"Added: {Type} at offset {Offset:X8}, size {Size} bytes, hash={HashAfter}";
            }

            return Type.ToString();
        }
    }

    /// <summary>
    /// Represents a known configuration flag location and its expected format.
    /// </summary>
    public sealed class ConfigFlagDefinition
    {
        public long Offset { get; set; }
        public int Size { get; set; } = 4;
        public string Name { get; set; }
        public byte[] DefaultMask { get; set; } // Mask to extract flag bits
        public bool IsBitFlag { get; set; }

        public static ConfigFlagDefinition Create(long offset, int size = 4, string name = null)
        {
            return new ConfigFlagDefinition
            {
                Offset = offset,
                Size = size,
                Name = name ?? $"flag_{offset:X8}"
            };
        }

        public static readonly List<ConfigFlagDefinition> CommonFlags = new()
        {
            // Example: Boot mode flags (common in many firmwares)
            ConfigFlagDefinition.Create(0x100, 4, "boot_mode"),
            ConfigFlagDefinition.Create(0x200, 4, "debug_enabled"),
            ConfigFlagDefinition.Create(0x300, 4, "factory_reset"),
            // Add more based on specific firmware analysis
        };
    }

    /// <summary>
    /// Represents a certificate or cryptographic blob found in the image.
    /// </summary>
    public sealed class CertificateInfo
    {
        public long Offset { get; set; }
        public int Size { get; set; }
        public string Hash { get; set; }
        public string? Fingerprint { get; set; }
        public byte[] RawData { get; set; }

        public static CertificateInfo Create(long offset, int size, byte[] data)
        {
            return new CertificateInfo
            {
                Offset = offset,
                Size = size,
                Hash = FirmwareChange.ComputeHash(data),
                Fingerprint = ComputeFingerprint(data),
                RawData = data
            };
        }

        public static string ComputeFingerprint(byte[] data)
        {
            if (data == null || data.Length == 0) return "empty";
            
            // Try to parse as X.509 certificate first
            try
            {
                using var ms = new MemoryStream(data);
                using var reader = new BinaryReader(ms);
                
                // Check for common certificate headers
                byte[] header = reader.ReadBytes(4);
                string? certType = null;

                if (header[0] == 0x30 && header[1] == 0x82)
                {
                    // ASN.1 SEQUENCE - likely X.509
                    certType = "X.509";
                }
                else if (header[0] == 0x30 && header[1] == 0x84)
                {
                    certType = "PKCS#7/DER";
                }

                // Compute SHA-256 fingerprint of the raw data
                using var sha256 = SHA256.Create();
                byte[] hashBytes = sha256.ComputeHash(data);
                string fingerprint = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                return $"{certType ?? "DER"}:{fingerprint}";
            }
            catch
            {
                // Fallback: just use the raw hash
                return $"DER:{FirmwareChange.ComputeHash(data)}";
            }
        }
    }

    /// <summary>
    /// Calculates entropy for a byte range using Shannon entropy formula.
    /// </summary>
    public static class EntropyCalculator
    {
        private const int DefaultWindowSize = 1024;
        private const double MinEntropyForBinary = 6.5; // Bits per byte

        public static double CalculateRangeEntropy(byte[] data, long startOffset, int length)
        {
            if (data == null || data.Length < startOffset + length)
                return 0;

            var slice = new byte[length];
            Array.Copy(data, (int)(startOffset & 0x7FFFFFFF), slice, 0, Math.Min(length, slice.Length));

            return CalculateEntropy(slice);
        }

        public static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;

            // Count frequency of each byte value
            var counts = new int[256];
            foreach (var b in data)
                counts[b]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = counts[i] / (double)data.Length;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return Math.Round(entropy, 3);
        }

        public static List<(long Offset, double Entropy)> FindEntropyAnomalies(byte[] data, int windowSize = DefaultWindowSize)
        {
            if (data == null || data.Length < windowSize * 2)
                return new List<(long, double)>();

            var anomalies = new List<(long, double)>();
            
            // Slide window and calculate entropy
            for (int i = 0; i <= data.Length - windowSize; i++)
            {
                var slice = new byte[windowSize];
                Array.Copy(data, i, slice);
                double entropy = CalculateEntropy(slice);

                // Flag as anomaly if significantly different from average
                if (entropy > MinEntropyForBinary + 0.5 || entropy < 1.0)
                {
                    anomalies.Add((i, Math.Round(entropy, 2)));
                }
            }

            return anomalies;
        }
    }

    /// <summary>
    /// Main binary diff engine for firmware images.
    /// </summary>
    public sealed class BinaryDiffEngine
    {
        private readonly string _image1Path;
        private readonly string _image2Path;
        private byte[] _image1Data;
        private byte[] _image2Data;

        public BinaryDiffEngine(string image1, string image2)
        {
            _image1Path = image1;
            _image2Path = image2;
        }

        /// <summary>
        /// Loads both images into memory.
        /// </summary>
        private void LoadImages()
        {
            _image1Data = File.ReadAllBytes(_image1Path);
            _image2Data = File.ReadAllBytes(_image2Path);
        }

        /// <summary>
        /// Performs the complete diff analysis and returns all detected changes.
        /// </summary>
        public List<FirmwareChange> Diff()
        {
            if (_image1Data == null || _image2Data == null)
                LoadImages();

            var changes = new List<FirmwareChange>();

            // 1. Compare file sizes and hashes first
            changes.AddRange(CompareFileMetadata());

            // 2. Find exact binary differences
            changes.AddRange(FindBinaryDifferences());

            // 3. Scan for config flag changes
            changes.AddRange(ScanConfigFlags());

            // 4. Detect certificate additions/modifications
            changes.AddRange(DetectCertificates());

            // 5. Analyze entropy shifts (potential new binaries)
            changes.AddRange(AnalyzeEntropyShifts());

            return changes;
        }

        private List<FirmwareChange> CompareFileMetadata()
        {
            var changes = new List<FirmwareChange>();

            if (_image1Data.Length != _image2Data.Length)
            {
                string type = _image2Data.Length > _image1Data.Length ? 
                    FirmwareChange.ChangeType.NewBinary : 
                    FirmwareChange.ChangeType.RemovedBinary;

                var desc = $"Size changed: {_image1Data.Length} → {_image2Data.Length} bytes";
                
                if (_image2Data.Length > _image1Data.Length)
                {
                    changes.Add(FirmwareChange.Create(type, desc + " (added)", 0, 
                        _image2Data.Length - _image1Data.Length));
                }
                else
                {
                    changes.Add(FirmwareChange.Create(type, desc + " (removed)", 0, 
                        _image1Data.Length - _image2Data.Length));
                }
            }

            // Compare root hashes
            string hash1 = FirmwareChange.ComputeHash(_image1Data);
            string hash2 = FirmwareChange.ComputeHash(_image2Data);

            if (hash1 != hash2)
            {
                changes.Add(FirmwareChange.Create(
                    FirmwareChange.ChangeType.ModifiedBinary,
                    $"Root hash changed: {hash1} → {hash2}",
                    0, _image1Data.Length));
            }

            return changes;
    }

        private List<FirmwareChange> FindBinaryDifferences()
        {
            var changes = new List<FirmwareChange>();
            int minLen = Math.Min(_image1Data.Length, _image2Data.Length);
            
            // Use rolling hash for faster comparison on large files
            const int BlockSize = 4096;
            const int SkipStep = 512;

            long lastDiffOffset = -1;
            int consecutiveMatches = 0;

            for (long i = 0; i < minLen; i += SkipStep)
            {
                // Compare blocks
                int blockLen = Math.Min(BlockSize, (int)(minLen - i));
                
                bool allMatch = true;
                for (int j = 0; j < blockLen; j++)
                {
                    if (_image1Data[i + j] != _image2Data[i + j])
                    {
                        allMatch = false;
                        break;
                    }
                }

                if (!allMatch)
                {
                    // Found a difference - report it with context
                    long diffOffset = i;
                    
                    // Find exact start of difference within this block
                    for (int j = 0; j < blockLen && i + j < minLen; j++)
                    {
                        if (_image1Data[i + j] != _image2Data[i + j])
                        {
                            diffOffset += j;
                            break;
                        }
                    }

                    // Find extent of difference
                    int diffSize = 0;
                    for (int j = 0; i + j < minLen && 
                         (_image1Data[i + j] == _image2Data[i + j] || 
                          lastDiffOffset != -1); j++)
                    {
                        if (_image1Data[i + j] != _image2Data[i + j])
                            diffSize++;
                        else if (diffSize > 0)
                            break;
                    }

                    // Merge consecutive differences to avoid fragmentation
                    if (lastDiffOffset == -1 || lastDiffOffset < i - BlockSize)
                    {
                        changes.Add(FirmwareChange.Create(
                            FirmwareChange.ChangeType.ModifiedBinary,
                            $"Binary diff at 0x{diffOffset:X8}",
                            _image1Data, _image2Data, diffOffset));
                        lastDiffOffset = i + Math.Min(blockLen, (int)(minLen - i));
                    }

                    consecutiveMatches = 0;
                }
                else
                {
                    consecutiveMatches++;
                }
            }

            return changes;
        }

        private List<FirmwareChange> ScanConfigFlags()
        {
            var changes = new List<FirmwareChange>();

            // Define common config flag offsets (extend based on firmware analysis)
            long[] knownOffsets = { 0x100, 0x200, 0x300, 0x400, 0x500 };

            foreach (var offset in knownOffsets)
            {
                if (offset >= _image1Data.Length || offset >= _image2Data.Length)
                    continue;

                byte[] val1 = new byte[4];
                byte[] val2 = new byte[4];
                
                Array.Copy(_image1Data, (int)(offset & 0x7FFFFFFF), val1, 0, 4);
                Array.Copy(_image2Data, (int)(offset & 0x7FFFFFFF), val2, 0, 4);

                if (!val1.SequenceEqual(val2))
                {
                    changes.Add(FirmwareChange.Create(
                        FirmwareChange.ChangeType.ConfigFlagChanged,
                        $"Config flag at 0x{offset:X8} changed",
                        val1, val2, offset));
                }
            }

            return changes;
        }

        private List<FirmwareChange> DetectCertificates()
        {
            var changes = new List<FirmwareChange>();

            // Known certificate offsets (common patterns)
            long[] certOffsets = { 0x1000, 0x2000, 0x3000, 0x4000 };

            foreach (var offset in certOffsets)
            {
                if (offset >= _image1Data.Length || offset >= _image2Data.Length)
                    continue;

                // Check for certificate-like structures
                int minCertSize = 512;
                int maxCertSize = Math.Min(4096, 
                    _image1Data.Length - (int)(offset & 0x7FFFFFFF));

                if (maxCertSize < minCertSize)
                    continue;

                // Scan for certificate headers in this range
                foreach (var certOffset in Enumerable.Range((int)offset, maxCertSize))
                {
                    byte[] header = new byte[4];
                    Array.Copy(_image1Data, certOffset, header);