require 'digest/sha2'
require 'openssl'
require 'json'

module Fwxray
  module BinaryDiff
    # Constants for chunking and detection
    CHUNK_SIZE = 64 * 1024
    HEADER_SIZES = {
      "ELF" => 64,
      "MZ" => 64,
      "PE32" => 64,
      "PE64" => 64,
      "Fat" => 28,
      "NTFS" => 512,
    }

    # Known certificate headers (partial)
    CERT_HEADERS = {
      "-----BEGIN CERTIFICATE-----",
      "-----BEGIN RSA PUBLIC KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "\x82\x03\x01" # DER/PEM boundary marker
    }

    class << self
      # Main entry point for binary diffing
      def compare_firmware(path_a, path_b)
        return { error: "File not found" } unless File.exist?(path_a) && File.exist?(path_b)
        
        size_a = File.size(path_a)
        size_b = File.size(path_b)

        # Handle completely different sized files
        if (size_a - size_b).abs > CHUNK_SIZE * 10
          return {
            error: "Files differ by more than 10MB",
            path_a_size: size_a,
            path_b_size: size_b,
            diff_type: "major"
          }
        end

        # Load files into memory (reasonable for firmware)
        data_a = File.binread(path_a)
        data_b = File.binread(path_b)

        # Calculate overall hash difference
        hash_diff = calculate_hash_diff(data_a, data_b)

        # Detect file type headers
        header_info = detect_headers(data_a, data_b)

        # Find certificate changes
        cert_changes = find_cert_changes(data_a, data_b)

        # Identify config sections
        config_changes = find_config_changes(data_a, data_b)

        # Detect entropy region shifts
        entropy_shifts = detect_entropy_shifts(data_a, data_b)

        # Calculate byte-level differences
        byte_diff = calculate_byte_diff(data_a, data_b)

        # Build comprehensive report
        report = {
          path_a: path_a,
          path_b: path_b,
          size_a: size_a,
          size_b: size_b,
          hash_diff: hash_diff,
          headers: header_info,
          certs: cert_changes,
          configs: config_changes,
          entropy: entropy_shifts,
          byte_diff: byte_diff,
          summary: generate_summary(hash_diff, byte_diff)
        }

        report
      end

      private

      def calculate_hash_diff(data_a, data_b)
        hash_a = Digest::SHA256.hexdigest(data_a)
        hash_b = Digest::SHA256.hexdigest(data_b)
        
        {
          a: hash_a,
          b: hash_b,
          identical: (hash_a == hash_b),
          hamming_distance: calculate_hamming_distance(hash_a, hash_b)
        }
      end

      def calculate_hamming_distance(str1, str2)
        return 0 if str1.length != str2.length
        
        distance = 0
        [str1, str2].each_with_index do |s, i|
          (0...s.length).each do |j|
            next unless s[j]
            distance += 1 if s[j] != (i == 0 ? str2[j] : str1[j])
          end
        end
        
        distance
      end

      def detect_headers(data_a, data_b)
        result = { a: {}, b: {} }
        
        HEADER_SIZES.each do |name, size|
          if data_a[0...size].bytes.to_s == name
            result[:a][name] = true
          end
          
          if data_b[0...size].bytes.to_s == name
            result[:b][name] = true
          end
        end

        # Check for common firmware headers
        [data_a, data_b].each_with_index do |d, i|
          next unless d.length >= 4
        
          # Check for U-Boot header signature
          if d[0...4].bytes.to_s == "\x01\xF2\x07\x36" || 
             d[0...4].bytes.to_s == "Uboot"
            result[:i][("u-boot" * i)] = true
          end

          # Check for FIT image header (Linux)
          if d[0...4].bytes.to_s == "\x46\x49\x54\x23" || 
             d[0...4].bytes.to_s == "FIT#"
            result[:i][("fit" * i)] = true
          end

          # Check for UBI header
          if d[0...4].bytes.to_s == "\x18\x53\x72\x6C" || 
             d[0...4].bytes.to_s == "UBI!"
            result[:i][("ubi" * i)] = true
          end
        end

        result
      end

      def find_cert_changes(data_a, data_b)
        certs_a = extract_certs_from_data(data_a)
        certs_b = extract_certs_from_data(data_b)

        # Compare certificates
        common = []
        only_in_a = []
        only_in_b = []
        
        all_a_hashes = certs_a.map { |c| Digest::SHA256.hexdigest(c) }
        all_b_hashes = certs_b.map { |c| Digest::SHA256.hexdigest(c) }

        # Find common certificates
        (all_a_hashes & all_b_hashes).each do |hash|
          common << { hash: hash, count: 0 }
        end

        # Find only in A
        (all_a_hashes - all_b_hashes).each do |hash|
          only_in_a << { hash: hash }
        end

        # Find only in B  
        (all_b_hashes - all_a_hashes).each do |hash|
          only_in_b << { hash: hash }
        end

        { common: common, only_in_a: only_in_a, only_in_b: only_in_b }
      end

      def extract_certs_from_data(data)
        certs = []
        
        # Look for PEM format certificates
        pem_pattern = /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/m
        
        data.scan(pem_pattern).each do |match|
          cert_content = match[1].strip
          next if cert_content.length < 50
            
            certs << cert_content
          end
        end

        # Also look for DER format (binary)
        der_markers = ["\x30\x82", "\x30\x86"]
        
        data.each_byte do |b|
          next unless [b, b + 1].join.to_s.start_with?("30")
          
            # Found potential DER start
            if (data[b...4].bytes.to_s == "3082" || 
                 data[b...4].bytes.to_s == "3086")
              certs << data[b..b+100]
              break
            end
          end
        end

        certs
      end

      def find_config_changes(data_a, data_b)
        configs = []
        
        # Common config file patterns and locations
        config_patterns = {
          "json" => /{.*}/m,
          "xml" => /<\?xml.*?<[^>]+>/m,
          "ini" => /^\s*\[.*?\]\s*|\s*[\w.]+\s*=.*/m,
          "yaml" => /^---.*\n|^(\s*)[-&:][^-\s].*/m,
        }

        # Search for config sections in both files
        [data_a, data_b].each_with_index do |d, i|
          (0...[d.length - 512]).step(64 * 1024) do |offset|
            chunk = d[offset..offset + 512]
            
            config_patterns.each do |type, pattern|
              matches = chunk.scan(pattern)
              next if matches.empty? || matches.length > 3
                
                configs << {
                  offset: offset,
                  type: type,
                  length: matches.first[0].length,
                  preview: matches.first[0][0...200]
                }
              end
            end
          end
        end

        # Group by similarity (likely same config)
        grouped = configs.group_by do |c|
          Digest::SHA1.hexdigest(c[:preview])
        end

        { raw: configs, grouped: grouped }
      end

      def detect_entropy_shifts(data_a, data_b)
        # Calculate entropy for chunks
        chunk_size = 4096
        
        def calculate_chunk_entropy(chunk)
          return 0 if chunk.length < 128
          
          # Shannon entropy calculation
          freq = Hash.new(0)
          chunk.each_byte { |b| freq[b] += 1 }
          
          total = chunk.length.to_f
          entropy = 0.0
          
          freq.each do |_, count|
            p = count / total
            entropy -= p * Math.log2(p) if p > 0
          end

          # Normalize to 0-8 range (max for byte data is 8)
          (entropy / 8.0) * 100
        end

        def find_high_entropy_regions(data, threshold = 75)
          regions = []
          
          (0...[data.length - chunk_size]).step(chunk_size) do |offset|
            chunk = data[offset..offset + chunk_size]
            entropy = calculate_chunk_entropy(chunk)
            
              if entropy > threshold && !regions.last || 
                 offset >= regions.last[:end] + 128
                regions << {
                  start: offset,
                  end: offset + chunk_size - 1,
                  entropy: entropy.round(2),
                  type: "high"
                }
              elsif entropy < threshold - 5 && !regions.empty?
                # End of high-entropy region
                regions.last[:end] = offset - 1
              end
            end

          if !regions.empty?
            regions << { start: regions.last[:start], 
                        end: data.length - 1,
                        entropy: calculate_chunk_entropy(data[regions.last[:start]..-1]),
                        type: "high" }
          end

          regions
        end

        high_a = find_high_entropy_regions(data_a)
        high_b = find_high_entropy_regions(data_b)

        # Compare region positions
        { a: high_a, b: high_b, shifted: compare_region_shifts(high_a, high_b) }
      end

      def compare_region_shifts(regions_a, regions_b)
        return { no_shift: true } if regions_a.empty? && regions_b.empty?

        # Normalize regions to percentages of file size
        size_a = File.size(File.basename(File.expand_path("a", regions_a.first[:start].to_s))) rescue 1024 * 1024
        size_b = File.size(File.basename(File.expand_path("b", regions_b.first[:start].to_s))) rescue 1024 * 1024

        # Simple comparison - check if major regions shifted significantly
        tolerance = 0.15 # 15% shift threshold
        
        a_normalized = regions_a.map { |r| (r[:start] / size_a.to_f) * 100 }
        b_normalized = regions_b.map { |r| (r[:start] / size_b.to_f) * 100 }

        # Check if corresponding regions shifted more than tolerance
        shifts_detected = []
        
        a_normalized.zip(b_normalized).each do |(pos_a, pos_b)|
          shift = (pos_a - pos_b).abs
          shifts_detected << { from: pos_a.round(2), to: pos_b.round(2), 
                              shift_pct: shift.round(2) } if shift > tolerance * 100
        end

        { shifted: !shifts_detected.empty?, shifts: shifts_detected,
          a_count: regions_a.length, b_count: regions_b.length }
      end

      def calculate_byte_diff(data_a, data_b)
        return { identical: true, diff_bytes: 0 } if data_a == data_b
        
        # Calculate number of different bytes
        max_len = [data_a.length, data_b.length].max
        min_len = [data_a.length, data_b.length].min
        
        diff_count = 0
        (0...min_len).each do |i|
          diff_count += 1 if data_a[i] != data_b[i]
        end

        # Add difference for length mismatch
        diff_count += ([data_a.length, data_b.length].max - min_len)

        { identical: false, diff_bytes: diff_count, 
          total_bytes: max_len, 
          diff_percentage: (diff_count.to_f / max_len * 100).round(2) }
      end

      def generate_summary(hash_diff, byte_diff)
        if hash_diff[:identical]
          "Identical images"
        elsif byte_diff[:diff_percentage] < 0.1
          "Minor changes (#{byte_diff[:diff_percentage]}%)"
        elsif byte_diff[:diff_percentage] < 5
          "Moderate changes (#{byte_diff[:diff_percentage]}%)"
        else
          "Major changes (#{byte_diff[:diff_percentage]}%)"
        end
      end

      # Public method to output report as JSON
      def output_json(report)
        puts JSON.pretty_generate(report)
      end

      # Public method to output human-readable summary
      def output_summary(report)
        puts "=" * 60
        puts "Firmware Binary Diff Report"
        puts "=" * 60
        puts "File A: #{report[:path_a]}"
        puts "Size:   #{format_size(report[:size_a])}"
        puts "File B: #{report[:path_b]}"
        puts "Size:   #{format_size(report[:size_b])}"
        puts "=" * 60
        
        if report[:hash_diff][:identical]
          puts "Status: IDENTICAL"
        else
          puts "Status: CHANGED (#{report[:byte_diff][:diff_percentage]}% different)"
          puts "Hash diff: #{report[:hash_diff][:hamming_distance]} bits changed"
        end

        # Headers found
        if report[:headers].any? { |k, v| k != :i && v.any? }
          puts "\nHeaders detected:"
          report[:headers].each do |key, values|
            next if key == :i
            next unless values.any?
            name = key.to_s.split(/(\d)/).first
            count = (values.count { |v| v }) - 1
            puts "  #{name}: found in #{count} file(s)"
          end
        end

        # Certificate changes
        if report[:certs][:only_in_a].any? || report[:certs][:only_in_b].any?
          puts "\nCertificate changes:"
          report[:certs][:only_in_a].each do |c|
            puts "  + Added in B: #{format_size(c[:hash][0...16])}..."
          end
          report[:certs][:only_in_b].each do |c|
            puts "  - Removed from A: #{format_size(c[:hash][0...16])}..."
          end
        elsif report[:certs][:common].any?
          puts "\nCommon certificates: #{report[:certs][:common].length}"
        end

        # Config changes
        if report[:configs][:grouped].any? { |k, v| k != :i && v.any? }
          puts "\nConfig sections found:"
          report[:configs][:grouped].each do |key, values|
            next if key == :i
            next unless values.any?
            type = key.to_s.split(/(\d)/).first
            count = (values.count { |v| v }) - 1
            puts "  #{type}: found in #{count} file(s)"
          end
        end

        # Entropy shifts
        if report[:entropy][:shifted]
          puts "\nEntropy region shifts detected:"
          report[:entropy][:shifts].each do |s|
            puts "  Shift: #{format_percent(s[:from])} -> #{format_percent(s[:to])}"
            puts "    Change: #{s[:shift_pct]}%"
          end
        elsif !report[:entropy][:a].empty? || !report[:entropy][:b].empty