#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <memory>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>

namespace fwxray {

constexpr size_t DEFAULT_BLOCK_SIZE = 4096;
constexpr uint32_t MAGIC_CERT = 0x2F000E15; // PEM header magic (approx)
constexpr uint32_t MAGIC_BIN = 0x7F454C46;   // ELF header

struct DiffRegion {
    size_t offset;
    size_t length;
    std::string category;
    std::vector<uint8_t> sample;
};

class BinaryDiff {
private:
    void* map1 = nullptr;
    void* map2 = nullptr;
    size_t len1 = 0, len2 = 0;
    size_t block_size_ = DEFAULT_BLOCK_SIZE;

    static uint32_t readMagic(const void* data) {
        return *reinterpret_cast<const uint32_t*>(data);
    }

    bool isBinary(const void* data, size_t offset) {
        auto m = readMagic(data + offset);
        return (m == MAGIC_BIN || m == 0x7F454C46 || 
                m == 0x01020304 || m > 0xFF);
    }

    bool isCert(const void* data, size_t offset) {
        auto m = readMagic(data + offset);
        return (m == MAGIC_CERT || 
                std::string(reinterpret_cast<const char*>(data+offset), 16).find("CERT") != std::string::npos);
    }

public:
    BinaryDiff() : block_size_(DEFAULT_BLOCK_SIZE) {}

    void load(const std::string& path, size_t* outLen = nullptr) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("open: " + std::string(strerror(errno)));

        len1 = lseek(fd, 0, SEEK_END);
        if (outLen) *outLen = len1;

        map1 = mmap(nullptr, len1, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (map1 == MAP_FAILED) throw std::runtime_error("mmap: " + std::string(strerror(errno)));
    }

    void load2(const std::string& path) {
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0) throw std::runtime_error("open: " + std::string(strerror(errno)));

        len2 = lseek(fd, 0, SEEK_END);

        map2 = mmap(nullptr, len2, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);

        if (map2 == MAP_FAILED) throw std::runtime_error("mmap: " + std::string(strerror(errno)));
    }

    void setBlockSize(size_t bs) { block_size_ = bs; }

    std::vector<DiffRegion> diff() const {
        std::vector<DiffRegion> regions;
        
        size_t minLen = len1 < len2 ? len1 : len2;
        for (size_t off = 0; off < minLen; off += block_size_) {
            if (memcmp(map1 + off, map2 + off, block_size_) != 0) {
                // Find exact boundary of difference
                size_t start = off;
                while (start > 0 && memcmp(map1 + start - 1, map2 + start - 1, 1) == 0) {
                    start--;
                }

                size_t end = off + block_size_;
                while (end < minLen && 
                       memcmp(map1 + end, map2 + end, 1) != 0) {
                    end++;
                }

                // Determine category
                std::string cat;
                if (isBinary(map1, start)) cat = "binary";
                else if (isCert(map1, start)) cat = "certificate";
                else if ((end - start) < 64 && 
                         memcmp(map1 + start, map2 + start, 8) == 0) {
                    // Config flag flip detection
                    auto val1 = *reinterpret_cast<uint32_t*>(map1 + start);
                    auto val2 = *reinterpret_cast<uint32_t*>(map2 + start);
                    if (val1 != val2 && 
                        ((val1 ^ val2) & 0xFFFF) == 0 ||
                        ((val1 ^ val2) & 0xFFFFFFFF) == 0x80000000) {
                        cat = "config_flag";
                    } else if (isBinary(map1, start)) {
                        cat = "binary";
                    } else {
                        cat = "entropy";
                    }

                } else {
                    cat = "unknown";
                }

                regions.emplace_back(start, end - start, std::move(cat));
            }
        }

        // Handle size differences
        if (len1 != len2) {
            if (len2 > len1) {
                regions.emplace_back(len1, len2 - len1, "added");
            } else {
                regions.emplace_back(len2, len1 - len2, "removed");
            }
        }

        return regions;
    }

    void cleanup() {
        if (map1) munmap(map1, len1);
        if (map2) munmap(map2, len2);
    }

    ~BinaryDiff() = default;
};

// CLI interface
class FwxrayDiff {
private:
    BinaryDiff diff_;
    bool verbose_ = false;

public:
    FwxrayDiff(bool v = false) : verbose_(v), diff_() {}

    void setVerbose(bool v) { verbose_ = v; }

    std::vector<DiffRegion> operator()(const std::string& oldPath, 
                                       const std::string& newPath) {
        try {
            diff_.load(oldPath);
            if (!verbose_) diff_.setBlockSize(8192); // Faster for large files
            else diff_.setBlockSize(DEFAULT_BLOCK_SIZE);
            
            diff_.load2(newPath);

            auto regions = diff_.diff();
            return regions;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << "\n";
            diff_.cleanup();
            throw;
        }
    }

    void cleanup() { diff_.cleanup(); }
};

// Demo / entry point
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: fwxray-diff <old_image> <new_image>\n";
        std::cout << "       --verbose\n";
        return 0;
    }

    bool verbose = false;
    for (int i = 1; i < argc && !verbose; ++i) {
        if (std::string(argv[i]) == "--verbose") verbose = true;
    }

    FwxrayDiff diff(verbose);
    
    try {
        auto regions = diff("firmware.bin", "firmware_new.bin");

        std::cout << "\n=== FWXRAY BINARY DIFF REPORT ===\n\n";
        
        if (regions.empty()) {
            std::cout << "No differences found.\n";
        } else {
            size_t totalBytes = 0;
            for (const auto& r : regions) {
                totalBytes += r.length;
            }

            std::cout << "Found " << regions.size() << " region(s), " 
                      << totalBytes << " bytes changed.\n\n";

            // Group by category
            std::vector<std::pair<std::string, std::vector<DiffRegion>>> groups;
            
            for (const auto& r : regions) {
                bool found = false;
                for (auto& [cat, vec] : groups) {
                    if (cat == r.category) {
                        vec.push_back(r);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    groups.emplace_back(r.category, std::vector<DiffRegion>{r});
                }
            }

            // Output grouped results
            for (const auto& [cat, vec] : groups) {
                std::cout << "[ " << cat << " ]\n";
                std::cout << "  Regions: " << vec.size() << ", Total: " 
                          << vec[0].length << " bytes\n";

                if (verbose || !vec.empty()) {
                    for (const auto& r : vec) {
                        std::cout << "    Offset: 0x" << std::hex << r.offset 
                                  << std::dec << ", Len: " << r.length << "\n";
                        
                        // Show sample bytes
                        if (!r.sample.empty()) {
                            std::cout << "      Sample diff:\n";
                            for (size_t i = 0; i < r.sample.size() && 
                                 i < 16 && i + r.offset < r.length; ++i) {
                                uint8_t b1 = *(map1 ? reinterpret_cast<const uint8_t*>(map1 + r.offset + i) : nullptr);
                                uint8_t b2 = *(map2 ? reinterpret_cast<const uint8_t*>(map2 + r.offset + i) : nullptr);
                                
                                std::cout << "        [" << std::setw(4) << i 
                                          << "] 0x" << std::hex 
                                          << (b1 ^ b2) << std::dec;
                            }
                        }
                    }
                }
            }
        }

    } catch (...) {
        diff.cleanup();
        return 1;
    }

    diff.cleanup();
    return 0;
}