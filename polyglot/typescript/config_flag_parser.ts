import { ConfigEntry, ChangeType, ConfigDiffResult, ParsedConfig } from './types';

export type ParseError = 
  | { kind: 'FORMAT_ERROR'; format: string; message: string }
  | { kind: 'VALIDATION_ERROR'; field: string; value: unknown; expected: string }
  | { kind: 'ENCODING_ERROR'; byteOffset: number; code: string };

export interface ParseOptions {
  strict?: boolean;
  normalizeKeys?: boolean;
  ignoreMissing?: boolean;
}

export class ConfigFlagParser {
  private static readonly DEFAULT_OPTIONS: ParseOptions = {
    strict: true,
    normalizeKeys: false,
    ignoreMissing: false,
  };

  public static parse(
    data: string | Buffer | Uint8Array,
    format?: 'json' | 'ini' | 'xml',
    options: ParseOptions = {}
  ): ParsedConfig {
    const opts = { ...this.DEFAULT_OPTIONS, ...options };
    
    try {
      if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
        return this.parseBinary(data, format, opts);
      }
      
      // Try to auto-detect format from content
      const detectedFormat = this.detectFormat(data as string);
      return ConfigFlagParser[detectedFormat](data as string, options);
    } catch (error) {
      if (opts.strict) {
        throw new ParseError({ kind: 'FORMAT_ERROR', format: format || 'auto', message: String(error) });
      }
      return this.createFallbackResult(String(error));
    }
  }

  private static parseBinary(
    data: Buffer | Uint8Array,
    format?: string,
    opts: ParseOptions = {}
  ): ParsedConfig {
    // Look for embedded JSON/XML in binary blobs
    const jsonMatch = data.toString('utf-8').match(/{"[^{}]*"}/);
    
    if (jsonMatch) {
      try {
        return ConfigFlagParser.json(data.toString('utf-8'), opts);
      } catch {
        // Fall through to other parsers
      }
    }

    const xmlMatch = data.toString('utf-8').match(/<[^>]+>/g);
    if (xmlMatch && format === 'xml') {
      return ConfigFlagParser.xml(data.toString('utf-8'), opts);
    }

    // Check for INI-style sections
    if (/^\[.*\]/.test(data.toString())) {
      return ConfigFlagParser.ini(data.toString(), opts);
    }

    throw new ParseError({ kind: 'FORMAT_ERROR', format: format || 'binary', message: 'No recognized config format found' });
  }

  private static detectFormat(content: string): 'json' | 'ini' | 'xml' {
    if (/^\s*\{/.test(content)) return 'json';
    if (/\[.*\]/.test(content)) return 'ini';
    if (/<[^>]+>/.test(content)) return 'xml';
    return 'auto';
  }

  private static json(
    content: string,
    opts: ParseOptions = {}
  ): ParsedConfig {
    let parsed;
    
    try {
      parsed = JSON.parse(content);
    } catch (e) {
      throw new ParseError({ kind: 'FORMAT_ERROR', format: 'json', message: String(e) });
    }

    // Normalize nested keys to dot notation
    const normalized = this.normalizeNestedKeys(parsed, opts.normalizeKeys);

    return {
      raw: content,
      parsed: normalized as Record<string, unknown>,
      meta: {
        format: 'json',
        byteLength: Buffer.from(content).length,
        timestamp: Date.now(),
      },
    };
  }

  private static ini(
    content: string,
    opts: ParseOptions = {}
  ): ParsedConfig {
    const lines = content.split(/\r?\n/);
    
    let currentSection: string | null = null;
    const result: Record<string, unknown> = {};

    for (const line of lines) {
      const trimmed = line.trim();
      
      if (!trimmed || trimmed.startsWith(';') || trimmed.startsWith('#')) continue;
      
      // Section header
      if (/^\[.*\]$/.test(trimmed)) {
        currentSection = trimmed.slice(1, -1).trim().toLowerCase();
        result[currentSection] = {};
        continue;
      }

      // Key-value pair
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1).trim();
        
        // Handle quoted values and escape sequences
        value = this.unescapeValue(value);

        if (currentSection) {
          result[currentSection][key] = value;
        } else {
          result[globalThis._root_ || 'global'] = key;
        }
      }
    }

    return {
      raw: content,
      parsed: result as Record<string, unknown>,
      meta: { format: 'ini', byteLength: Buffer.from(content).length },
    };
  }

  private static xml(
    content: string,
    opts: ParseOptions = {}
  ): ParsedConfig {
    // Simple XML parser for common firmware config structures
    const rootMatch = content.match(/<\s*[^>]+>/);
    
    if (!rootMatch) {
      throw new ParseError({ kind: 'FORMAT_ERROR', format: 'xml', message: 'No root element found' });
    }

    // Extract attributes and text content
    const attrs: Record<string, string> = {};
    let textContent = '';

    const rootTag = rootMatch[0];
    const attrRegex = /(\w+)="([^"]*)"/g;
    
    while (attrRegex.test(rootTag)) {
      const match = attrRegex.exec(rootTag);
      attrs[match![1]] = match![2];
    }

    // Extract text content between tags
    const textMatch = rootTag.match(/>([^<]*)</);
    if (textMatch) {
      textContent = textMatch[1].trim();
    }

    return {
      raw: content,
      parsed: {
        ...attrs,
        value: textContent || '',
      },
      meta: { format: 'xml', byteLength: Buffer.from(content).length },
    };
  }

  private static unescapeValue(value: string): string {
    const escapes: Record<string, string> = {
      '\\\\': '\\',
      '\\"': '"',
      "\\'": "'",
      '\\n': '\n',
      '\\r': '\r',
      '\\t': '\t',
      '\\0': '\0',
    };

    let result = value;
    
    for (const [escape, replacement] of Object.entries(escapes)) {
      result = result.replace(new RegExp(escape.replace(/\\/, '\\\\'), 'g'), replacement);
    }

    return result;
  }

  private static normalizeNestedKeys(
    obj: Record<string, unknown>,
    flatten: boolean
  ): Record<string, unknown> {
    if (!flatten) return obj as Record<string, unknown>;

    const result: Record<string, unknown> = {};

    function traverse(current: Record<string, unknown>, prefix: string = '') {
      for (const [key, value] of Object.entries(current)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        
        if (value && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value as Buffer)) {
          traverse(value as Record<string, unknown>, fullKey);
        } else {
          result[fullKey] = value;
        }
      }
    }

    traverse(obj);
    return result;
  }

  private static createFallbackResult(message: string): ParsedConfig {
    return {
      raw: message,
      parsed: {},
      meta: { format: 'fallback', byteLength: Buffer.from(message).length },
    };
  }
}

// ============================================================================
// DIFF ENGINE - Compare two configs and surface changes
// ============================================================================

export class ConfigDiffEngine {
  private static readonly CHANGE_THRESHOLD = 0.1; // 10% threshold for "significant" change

  public static diff(
    oldConfig: ParsedConfig,
    newConfig: ParsedConfig,
    options?: { ignoreKeys?: string[]; includeMeta?: boolean }
  ): ConfigDiffResult {
    const opts = { ignoreKeys: [], includeMeta: false, ...options };
    
    if (!opts.includeMeta) {
      oldConfig.parsed = this.extractData(oldConfig);
      newConfig.parsed = this.extractData(newConfig);
    }

    const diff = this.calculateDiff(
      oldConfig.parsed as Record<string, unknown>,
      newConfig.parsed as Record<string, unknown>,
      opts.ignoreKeys
    );

    return {
      old: oldConfig.meta,
      new: newConfig.meta,
      changes: diff.changes,
      summary: this.generateSummary(diff),
      isSignificant: diff.isSignificant,
    };
  }

  private static extractData(config: ParsedConfig): Record<string, unknown> {
    if (config.parsed && typeof config.parsed === 'object') {
      return config.parsed;
    }
    return {};
  }

  private static calculateDiff(
    oldData: Record<string, unknown>,
    newData: Record<string, unknown>,
    ignoreKeys: string[] = []
  ): { changes: ChangeType[]; isSignificant: boolean } {
    const allKeys = new Set([...Object.keys(oldData), ...Object.keys(newData)]);
    
    let addedCount = 0;
    let removedCount = 0;
    let modifiedCount = 0;

    const changes: ChangeType[] = [];

    for (const key of allKeys) {
      if (ignoreKeys.includes(key)) continue;

      const oldValue = oldData[key];
      const newValue = newData[key];

      if (!oldValue && newValue !== undefined) {
        // Added
        addedCount++;
        changes.push({ type: 'ADDED', key, oldValue: null, newValue });
      } else if (oldValue && !newValue) {
        // Removed
        removedCount++;
        changes.push({ type: 'REMOVED', key, oldValue, newValue: null });
      } else if (this.valuesDiffer(oldValue, newValue)) {
        // Modified
        modifiedCount++;
        const diffType = this.determineChangeType(oldValue, newValue);
        changes.push({ 
          type: diffType, 
          key, 
          oldValue, 
          newValue 
        });
      }
    }

    return {
      changes,
      isSignificant: (addedCount + removedCount + modifiedCount) / Math.max(1, allKeys.size) > this.CHANGE_THRESHOLD,
    };
  }

  private static valuesDiffer(a: unknown, b: unknown): boolean {
    if (a === b) return false;
    
    if (typeof a !== typeof b) return true;

    if (Buffer.isBuffer(a)) {
      // Compare buffers by length and content hash
      const aHash = this.bufferToHex(a);
      const bHash = Buffer.isBuffer(b) ? this.bufferToHex(b) : '';
      return aHash !== bHash;
    }

    if (typeof a === 'object' && typeof b === 'object') {
      // Compare objects by stringified form
      try {
        return JSON.stringify(a) !== JSON.stringify(b);
      } catch {
        return true;
      }
    }

    return true;
  }

  private static determineChangeType(oldValue: unknown, newValue: unknown): ChangeType {
    if (Buffer.isBuffer(newValue)) {
      return 'BINARY_ADDED';
    }
    
    if (Buffer.isBuffer(oldValue) && !Buffer.isBuffer(newValue)) {
      return 'BINARY_REMOVED';
    }

    // Check for boolean flips
    const oldBool = this.toBoolean(oldValue);
    const newBool = this.toBoolean(newValue);
    if (oldBool !== newBool) {
      return 'BOOLEAN_FLIP';
    }

    // Check for numeric shifts
    const oldNum = Number(oldValue);
    const newNum = Number(newValue);
    if (!isNaN(oldNum) && !isNaN(newNum)) {
      const shift = Math.abs(newNum - oldNum);
      if (shift > 0 && shift < 100) {
        return 'NUMERIC_SHIFT';
      }
    }

    // Check for certificate additions
    if (newValue && typeof newValue === 'string' && 
        /-----BEGIN CERTIFICATE-----/.test(newValue)) {
      return 'CERT_ADDED';
    }

    // Default to MODIFIED
    return 'MODIFIED';
  }

  private static toBoolean(value: unknown): boolean | null {
    if (value === null || value === undefined) return null;
    
    const str = String(value).toLowerCase().trim();
    if (str === 'true' || str === '1' || str === 'yes') return true;
    if (str === 'false' || str === '0' || str === 'no') return false;
    
    return null;
  }

  private static bufferToHex(buffer: Buffer): string {
    return buffer.toString('hex');
  }

  private static generateSummary(diff: { changes: ChangeType[] }): string {
    const counts = diff.changes.reduce((acc, change) => {
      acc[change.type] = (acc[change.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    let summary = '';
    
    if (!Object.keys(counts).length) {
      summary = 'No significant changes detected.';
    } else {
      const parts: string[] = [];
      
      for (const [type, count] of Object.entries(counts)) {
        switch (type) {
          case 'ADDED':
            parts.push(`${count} new flag${count !== 1 ? 's' : ''}`);
            break;
          case 'REMOVED':
            parts.push(`${count} removed flag${count !== 1 ? 's' : ''}`);
            break;
          case 'BOOLEAN_FLIP':
            parts.push(`${count} boolean flip${count !== 1 ? 's' : ''}`);
            break;
          case 'CERT_ADDED':
            parts.push(`${count} certificate${count !== 1 ? 's' : ''}`);
            break;
          case 'NUMERIC_SHIFT':
            parts.push(`${count} numeric shift${count !== 1 ? 's' : ''}`);
            break;
          default:
            parts.push(`${count} modification${count !== 1 ? 's' : ''}`);
        }
      }

      summary = `Found ${Object.values(counts).reduce((a, b) => a + b, 0)} change${Object.values(counts).reduce((a, b) => a + b, 0) !== 1 ? 's' : ''}: ${parts.join(', ')}`;
    }

    return summary;
  }
}

// ============================================================================
// ENTROPY REGION DETECTOR - Find shifted/random regions in binary
// ============================================================================

export class EntropyRegionDetector {
  private static readonly MIN_ENTROPY = 7.5; // Shannon entropy threshold
  private static readonly MIN_SIZE = 64;     // Minimum region size
  private static readonly WINDOW_SIZE = 256; // Analysis window

  public static detect(
    data: Buffer | Uint8Array,
    options?: { minEntropy?: number; maxSize?: number }
  ): Array<{ start: number; end: number; entropy: number }> {
    const opts = { minEntropy: this.MIN_ENTROPY, maxSize: 4096, ...options };

    if (!Buffer.isBuffer(data) && !(data instanceof Uint8Array)) {
      data = Buffer.from(data);
    }

    const byteLength = data.length;
    const results: Array<{ start: number; end: number; entropy: number }> = [];

    // Sliding window analysis
    for (let i = 0; i < byteLength - this.WINDOW_SIZE + 1; i += 32) {
      const windowEnd = Math.min(i + this.WINDOW_SIZE, byteLength);
      const windowData = data.slice(i, windowEnd);

      const entropy = this.calculateShannonEntropy(windowData);

      if (entropy >= opts.minEntropy && windowData.length >= opts.maxSize) {
        // Check if we already have a region covering this area
        let merged = false;
        
        for (const existing of results) {
          if (i <= existing.end + 32 && i + this.WINDOW_SIZE - 1 >= existing.start - 32) {
            // Merge regions
            existing.start = Math.min(existing.start, i);
            existing.end = Math.max(existing.end, i + this.WINDOW_SIZE - 1);
            merged = true;
            break;
          }
        }

        if (!merged