import * as fs from 'fs';
import * as path from 'path';
import { Buffer } from 'buffer';

// ============================================================================
// CONFIGURATION & TYPES
// ============================================================================

interface DiffOptions {
  blockSize: number;           // Block size for comparison (default: 4096)
  entropyThreshold: number;    // Shannon entropy threshold (0-8, default: 7.5)
  minEntropyRegionSize: number;// Minimum contiguous bytes to consider a region
  hashAlgorithm: 'md5' | 'sha1' | 'sha256';
  outputFormat: 'text' | 'json';
}

interface DiffResult {
  files: { name: string; size: number; sha256: string }[];
  summary: {
    identicalBytes: number;
    changedBytes: number;
    newBlocks: number;
    modifiedBlocks: number;
    deletedBlocks: number;
    entropyRegions: DiffResult['entropyRegions'];
    certChanges: DiffResult['certChanges'];
    configFlags: DiffResult['configFlags'];
  };
  blocks: {
    offset: number;
    size: number;
    status: 'identical' | 'modified' | 'added' | 'deleted';
    sha256?: string;
    details?: string[];
  }[];
  entropyRegions: Array<{
    type: 'new' | 'removed' | 'shifted';
    offset: number;
    size: number;
    avgEntropy: number;
    peakEntropy: number;
    likelyContent: 'crypto' | 'compressed' | 'unknown';
  }>;
  certChanges: Array<{
    type: 'new' | 'removed' | 'modified';
    offset: number;
    size: number;
    subject?: string;
    issuer?: string;
    expiry?: Date;
  }>;
  configFlags: Array<{
    name: string;
    oldValue: string | boolean | null;
    newValue: string | boolean | null;
    type: 'bit' | 'string' | 'number';
  }>;
}

interface Block {
  offset: number;
  data: Buffer;
  sha256?: string;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

const DEFAULT_OPTIONS: DiffOptions = {
  blockSize: 4096,
  entropyThreshold: 7.5,
  minEntropyRegionSize: 1024,
  hashAlgorithm: 'sha256',
  outputFormat: 'text',
};

function createHash(buffer: Buffer): string {
  const algo = DEFAULT_OPTIONS.hashAlgorithm;
  let hash: any;
  
  switch (algo) {
    case 'md5':
      hash = require('crypto').createHash('md5');
      break;
    case 'sha1':
      hash = require('crypto').createHash('sha1');
      break;
    default: // sha256
      hash = require('crypto').createHash('sha256');
  }
  
  return hash.update(buffer).digest('hex').toUpperCase();
}

function calculateShannonEntropy(data: Buffer): number {
  if (data.length === 0) return 0;
  
  const freq: Record<string, number> = {};
  for (const byte of data) {
    freq[byte.toString()] = (freq[byte.toString()] || 0) + 1;
  }
  
  let entropy = 0;
  const total = data.length;
  for (const count of Object.values(freq)) {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }
  
  return entropy;
}

function detectLikelyContent(entropy: number, offset: number): string {
  // Common firmware header signatures
  const headers: Record<string, [number, number]> = {
    'U-Boot': [[0x43, 0x42], [0x55, 0x42]],     // "CB" or "UB" magic
    'FIT':   [[0x46, 0x49, 0x54, 0x01]],        // FIT header
    'PEM':   [[0x50, 0x45, 0x4D, 0x0A]],        // PEM header
    'DER':   [[0x30, 0x82]],                     // DER sequence start
  };
  
  const data = Buffer.from([offset & 0xFF, (offset >> 8) & 0xFF]);
  for (const [name, magic] of Object.entries(headers)) {
    if (data.every((b, i) => b === magic[i])) {
      return name;
    }
  }
  
  // High entropy with reasonable size = likely crypto/compressed
  if (entropy > DEFAULT_OPTIONS.entropyThreshold && 
      offset % 4096 < 512) {
    return 'crypto';
  }
  
  return 'unknown';
}

// ============================================================================
// MEMORY MAPPED FILE HANDLING
// ============================================================================

class MemoryMappedFile {
  private file: fs.promises.FileHandle;
  private size: number;
  private readonly blockSize: number;
  private blockCache: Map<number, Buffer> = new Map();
  
  constructor(filePath: string, blockSize: number) {
    this.file = fs.openSync(filePath, 'r');
    this.size = fs.fstatSync(this.file).size;
    this.blockSize = blockSize;
  }
  
  async close(): Promise<void> {
    await this.file.close();
  }
  
  readBlock(offset: number): Buffer | null {
    if (offset < 0 || offset >= this.size) return null;
    
    const blockOffset = offset % this.blockSize;
    const cachedKey = Math.floor(offset / this.blockSize);
    
    // Try cache first
    if (this.blockCache.has(cachedKey)) {
      return this.blockCache.get(cachedKey)!;
    }
    
    // Read from file
    const start = offset - blockOffset;
    let data: Buffer | null = null;
    
    try {
      data = fs.readSync(this.file, 0, this.blockSize, start);
      
      if (data.length === 0) return null;
      
      // Pad to full block size if partial read at end of file
      while (data.length < this.blockSize && offset + this.blockSize <= this.size) {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
    } catch (err: any) {
      return null;
    }
    
    // Cache the block
    this.blockCache.set(cachedKey, data.slice(0, this.blockSize));
    return data.slice(0, this.blockSize);
  }
  
  getSize(): number {
    return this.size;
  }
}

// ============================================================================
// CERTIFICATE PARSING
// ============================================================================

interface CertInfo {
  subject: string | null;
  issuer: string | null;
  expiry: Date | null;
  validFrom: Date | null;
  serial: string | null;
}

function parseX509Cert(data: Buffer): CertInfo | null {
  try {
    // Try PEM format first (text with headers)
    const pemMatch = data.toString().match(/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s);
    
    if (pemMatch && pemMatch[1]) {
      return parsePEM(pemMatch[1]);
    }
    
    // Try DER format
    try {
      return parseDER(data);
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

function parsePEM(pem: string): CertInfo | null {
  const lines = pem.split('\n');
  let base64Data: string = '';
  
  for (const line of lines) {
    if (!line.startsWith('-----')) {
      base64Data += line.trim();
    }
  }
  
  try {
    // Remove padding and decode
    const cleanBase64 = base64Data.replace(/[^A-Za-z0-9+\/=]/g, '');
    const derBuffer = Buffer.from(cleanBase64, 'base64');
    
    return parseDER(derBuffer);
  } catch {
    return null;
  }
}

function parseDER(der: Buffer): CertInfo | null {
  try {
    // Simple ASN.1 DER parser for X.509 certificates
    const cert = x509.parse(der);
    
    if (!cert.tbsCertificate) return null;
    
    // Extract subject and issuer (simplified)
    let subject: string | null = null;
    let issuer: string | null = null;
    
    try {
      const subjectStr = cert.tbsCertificate.subject.toString('utf8');
      if (subjectStr) {
        subject = subjectStr.replace(/CN=([^,]+)/, '$1').trim();
      }
    } catch {}
    
    try {
      const issuerStr = cert.tbsCertificate.issuer.toString('utf8');
      if (issuerStr) {
        issuer = issuerStr.replace(/CN=([^,]+)/, '$1').trim();
      }
    } catch {}
    
    // Extract dates
    let expiry: Date | null = null;
    let validFrom: Date | null = null;
    
    try {
      if (cert.tbsCertificate.validity) {
        const notBefore = cert.tbsCertificate.validity.notBefore?.toDateString();
        const notAfter = cert.tbsCertificate.validity.notAfter?.toDateString();
        
        validFrom = notBefore ? new Date(notBefore) : null;
        expiry = notAfter ? new Date(notAfter) : null;
      }
    } catch {}
    
    // Extract serial number
    let serial: string | null = null;
    try {
      if (cert.tbsCertificate.version >= 2 && cert.tbsCertificate.serialNumber) {
        serial = cert.tbsCertificate.serialNumber.toString(16).toUpperCase();
      }
    } catch {}
    
    return { subject, issuer, expiry, validFrom, serial };
  } catch {
    return null;
  }
}

// ============================================================================
// CONFIG FLAG EXTRACTION (Common Firmware Headers)
// ============================================================================

interface ConfigFlag {
  name: string;
  offset: number;
  size: number;
  type: 'bit' | 'string' | 'number';
  defaultValue?: any;
}

function extractConfigFlags(fileData: Buffer): ConfigFlag[] {
  const flags: ConfigFlag[] = [];
  
  // Common header offsets and patterns
  const headers: Record<string, ConfigFlag[]> = {
    'U-Boot': [
      { name: 'bootcmd', offset: 0x100, size: 256, type: 'string' },
      { name: 'console', offset: 0x140, size: 32, type: 'string' },
    ],
    'FIT': [
      { name: 'compression', offset: 0x10, size: 4, type: 'number' },
    ],
  };
  
  for (const [name, headerFlags] of Object.entries(headers)) {
    // Check if this header is present
    const magic = Buffer.from(name.split('').map(c => c.charCodeAt(0)));
    if (fileData.slice(0, name.length).every((b, i) => b === name.charCodeAt(i))) {
      for (const flag of headerFlags) {
        try {
          let value: any;
          
          switch (flag.type) {
            case 'string':
              const strEnd = fileData.indexOf(0x00, flag.offset);
              value = strEnd > flag.offset 
                ? fileData.slice(flag.offset, strEnd).toString('utf8').trim()
                : null;
              break;
            case 'number':
              value = fileData.readUInt32LE(flag.offset) & 0xFFFF;
              break;
            case 'bit':
              const byteOffset = Math.floor((flag.offset - flag.size) / 8);
              const bitOffset = (flag.offset - flag.size) % 8;
              value = ((fileData.readUInt8(byteOffset) >> bitOffset) & 1) === 1;
              break;
          }
          
          flags.push({ ...flag, defaultValue: value });
        } catch {
          // Skip if parsing fails
        }
      }
    }
  }
  
  return flags;
}

// ============================================================================
// ENTROPY REGION DETECTION
// ============================================================================

function detectEntropyRegions(
  fileData: Buffer, 
  options: DiffOptions
): Array<{ offset: number; size: number; avgEntropy: number; peakEntropy: number }> {
  const regions: any[] = [];
  let currentRegion: any = null;
  
  for (let i = 0; i < fileData.length - options.minEntropyRegionSize + 1; i += options.blockSize) {
    const block = fileData.slice(i, i + options.blockSize);
    const entropy = calculateShannonEntropy(block);
    
    if (entropy > options.entropyThreshold) {
      // Start or continue a region
      if (!currentRegion) {
        currentRegion = { offset: i, size: 0, entropies: [] };
      }
      
      currentRegion.size += block.length;
      currentRegion.entropies.push(entropy);
    } else if (currentRegion && 
               currentRegion.size >= options.minEntropyRegionSize) {
      // End a region
      const avg = currentRegion.entropies.reduce((a, b) => a + b, 0) / currentRegion.entropies.length;
      const peak = Math.max(...currentRegion.entropies);
      
      regions.push({
        offset: currentRegion.offset,
        size: currentRegion.size,
        avgEntropy: avg,
        peakEntropy: peak,
      });
      
      currentRegion = null;
    } else if (currentRegion) {
      // Extend region with lower entropy
      currentRegion.size += block.length;
      currentRegion.entropies.push(entropy);
    }
  }
  
  // Don't forget the last region
  if (currentRegion && currentRegion.size >= options.minEntropyRegionSize) {
    const avg = currentRegion.entropies.reduce((a, b) => a + b, 0) / currentRegion.entropies.length;
    const peak = Math.max(...currentRegion.entropies);
    
    regions.push({
      offset: currentRegion.offset,
      size: currentRegion.size,
      avgEntropy: avg,
      peakEntropy: peak,
    });
  }
  
  return regions;
}

// ============================================================================
// BLOCK-BY-BLOCK COMPARISON (Sliding Window)
// ============================================================================

function compareFiles(
  file1Path: string, 
  file2Path: string,
  options: DiffOptions
): { blocks: any[]; result: DiffResult } {
  const m1 = new MemoryMappedFile(file1Path, options.blockSize);
  const m2 = new MemoryMappedFile(file2Path, options.blockSize);
  
  const blockSize = options.blockSize;
  const maxOffset = Math.max(m1.getSize(), m2.getSize());
  
  let identicalBytes = 0;
  let changedBytes = 0;
  let newBlocks = 0;
  let modifiedBlocks = 0;
  let deletedBlocks = 0;
  
  const blocks: any[] = [];
  
  // Create a rolling hash for efficient comparison
  function createRollingHash(block: Buffer): string {
    return createHash(block);
  }
  
  // Compare files of similar size (most common case)
  if (Math.abs(m1.getSize() - m2.getSize()) < blockSize * 4) {
    const minSize = Math.min(m1.getSize(), m2.getSize());
    
    for (let offset = 0; offset < minSize; offset += blockSize) {
      const b1 = m1.readBlock(offset);
      const b2 = m2.readBlock(offset);
      
      if (!b1 || !b2) continue;
      
      const h1 = createRollingHash(b1);
      const h2 = createRollingHash(b2);
      
      let status: any;
      let details: string[] = [];
      
      if (h1 === h2) {
        status = 'identical';
        identicalBytes += b1.length;
      } else {
        // Calculate actual changed bytes using XOR
        const xor = Buffer.from(b1).xor(Buffer.from(b2));
        const changedCount = xor.reduce((acc, byte) => acc + (byte ? 1 : 0), 0);
        
        if (changedCount > b1.length * 0.5) {
          status = 'modified';
          modifiedBlocks++;
          details.push(`~${(changedCount / b1.length *