/*
 * polyglot/c/binary_diff.c - fwxray binary diff engine
 * 
 * Compares two firmware images and reports:
 *   - New/removed blocks (binary changes)
 *   - Flipped config flags (small deltas)
 *   - Added entropy regions (likely certs/random data)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <math.h>

/* Configuration constants */
#define BLOCK_SIZE 4096
#define ENTROPY_WINDOW 256
#define ENTROPY_THRESHOLD 7.5
#define CONFIG_MAX_DELTA 32
#define MAX_ENTROPY_REGIONS 100

/* Memory mapping flags */
#define PROT_READ   (PROT_READ | PROT_WRITE)

/* Change types for diff output */
typedef enum {
    CHG_NONE,
    CHG_NEW_BLOCK,
    CHG_REMOVED_BLOCK,
    CHG_MODIFIED_BLOCK,
    CHG_CONFIG_FLIP,
    CHG_ENTROPY_ADDED,
    CHG_ENTROPY_SHIFTED
} ChangeType;

/* A single change record */
typedef struct {
    ChangeType type;
    uint64_t offset;          /* Offset in original/new file */
    size_t length;            /* Size of the change */
    uint8_t  *sample_data;    /* Small sample for inspection (max CONFIG_MAX_DELTA) */
} ChangeRecord;

/* Entropy region record */
typedef struct {
    uint64_t start_offset;
    size_t   length;
    double   entropy;
    int      is_new;          /* 1 = new, 0 = shifted */
} EntropyRegion;

/* Main diff context - holds state during comparison */
typedef struct {
    void     *img_a;         /* First image (reference) */
    size_t   img_a_size;
    void     *img_b;         /* Second image (new) */
    size_t   img_b_size;
    
    ChangeRecord  *changes;      /* Allocated change records */
    size_t        num_changes;
    size_t        changes_cap;
    
    EntropyRegion *entropy_regions;
    size_t        entropy_count;
} DiffContext;

/* Calculate Shannon entropy of a byte buffer */
static double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    
    unsigned char freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2((double)p);
        }
    }
    
    return entropy;
}

/* Check if a window has high entropy */
static int is_high_entropy(const uint8_t *data, size_t len, double threshold) {
    if (len < ENTROPY_WINDOW) return 0;
    
    /* Use sliding window to find max entropy in region */
    double max_ent = 0.0;
    for (size_t i = 0; i + ENTROPY_WINDOW <= len; i++) {
        double ent = calc_entropy(data + i, ENTROPY_WINDOW);
        if (ent > max_ent) max_ent = ent;
    }
    
    return max_ent >= threshold;
}

/* Extract entropy region from a file */
static int extract_entropy_region(DiffContext *ctx, 
                                   uint64_t offset, 
                                   size_t len,
                                   double threshold,
                                   int is_new) {
    if (len < ENTROPY_WINDOW) return 0;
    
    /* Sample the region to confirm entropy level */
    double ent = calc_entropy((uint8_t*)ctx->img_b + offset, len);
    
    if (ent >= threshold) {
        EntropyRegion *reg = &ctx->entropy_regions[ctx->entropy_count];
        reg->start_offset = offset;
        reg->length = len;
        reg->entropy = ent;
        reg->is_new = is_new;
        
        ctx->entropy_count++;
        if (ctx->entropy_count >= MAX_ENTROPY_REGIONS) {
            /* Merge or truncate - for now, just note we hit limit */
            return 1;
        }
    }
    
    return 0;
}

/* Compare two memory regions and report differences */
static int compare_regions(DiffContext *ctx, 
                           uint64_t offset_a, size_t len_a,
                           uint64_t offset_b, size_t len_b) {
    if (len_a == 0 && len_b == 0) return 0;
    
    /* Handle different lengths */
    size_t common_len = len_a < len_b ? len_a : len_b;
    int new_bytes = 0;
    int removed_bytes = 0;
    
    if (len_a > len_b) {
        removed_bytes = len_a - len_b;
    } else if (len_b > len_a) {
        new_bytes = len_b - len_a;
    }
    
    /* Check for actual byte differences in common region */
    int modified = 0;
    size_t diff_count = 0;
    
    for (size_t i = 0; i < common_len && diff_count < CONFIG_MAX_DELTA; i++) {
        if ((uint8_t*)ctx->img_a[offset_a + i] != 
            (uint8_t*)ctx->img_b[offset_b + i]) {
            modified = 1;
            diff_count++;
        }
    }
    
    /* Classify the change */
    if (modified && new_bytes == 0 && removed_bytes == 0) {
        ctx->changes[ctx->num_changes].type = CHG_MODIFIED_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_a;
        ctx->changes[ctx->num_changes].length = common_len;
    } else if (new_bytes > 0 && removed_bytes == 0) {
        ctx->changes[ctx->num_changes].type = CHG_NEW_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_b - new_bytes;
        ctx->changes[ctx->num_changes].length = len_b;
    } else if (removed_bytes > 0 && new_bytes == 0) {
        ctx->changes[ctx->num_changes].type = CHG_REMOVED_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_a;
        ctx->changes[ctx->num_changes].length = len_a;
    } else if (modified && new_bytes > 0) {
        /* New block with modifications - treat as new */
        ctx->changes[ctx->num_changes].type = CHG_NEW_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_b - new_bytes;
        ctx->changes[ctx->num_changes].length = len_b;
    } else if (modified && removed_bytes > 0) {
        /* Removed block with modifications */
        ctx->changes[ctx->num_changes].type = CHG_REMOVED_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_a;
        ctx->changes[ctx->num_changes].length = len_a;
    } else if (modified) {
        /* Pure modification */
        ctx->changes[ctx->num_changes].type = CHG_MODIFIED_BLOCK;
        ctx->changes[ctx->num_changes].offset = offset_a;
        ctx->changes[ctx->num_changes].length = common_len;
    }
    
    return modified ? 1 : 0;
}

/* Scan for config flag flips - small, sparse changes */
static int scan_config_flips(DiffContext *ctx) {
    /* Look for 4-byte and 8-byte patterns that might be flags */
    uint64_t a_size = ctx->img_a_size;
    uint64_t b_size = ctx->img_b_size;
    
    if (a_size < 12 || b_size < 12) return 0;
    
    /* Scan in blocks, looking for small deltas */
    size_t block_size = 8192;
    uint64_t min_offset = a_size > b_size ? a_size - block_size : 0;
    
    while (min_offset < a_size && min_offset < b_size) {
        /* Compare aligned 4-byte values */
        for (size_t off = 0; off + 8 <= block_size; off += 4) {
            uint32_t val_a, val_b;
            
            if ((uint64_t)(min_offset + off) < a_size && 
                (uint64_t)(min_offset + off) < b_size) {
                val_a = *(uint32_t*)((char*)ctx->img_a + min_offset + off);
                val_b = *(uint32_t*)((char*)ctx->img_b + min_offset + off);
                
                if (val_a != val_b && 
                    ((val_a ^ val_b) < 0x10000 || (val_a ^ val_b) > 0xFFFFF)) {
                    
                    /* Check if this looks like a flag flip */
                    uint32_t diff = val_a ^ val_b;
                    int is_flag_like = 0;
                    
                    /* Single bit flip, or power of 2 */
                    if ((diff & (diff - 1)) == 0) {
                        is_flag_like = 1;
                    }
                    /* Small delta in a config-like range */
                    else if (diff < 0x8000 || diff > 0xF0000000) {
                        is_flag_like = 1;
                    }
                    
                    if (is_flag_like) {
                        ctx->changes[ctx->num_changes].type = CHG_CONFIG_FLIP;
                        ctx->changes[ctx->num_changes].offset = min_offset + off;
                        ctx->changes[ctx->num_changes].length = 4;
                        
                        /* Copy sample data */
                        memcpy(ctx->changes[ctx->num_changes].sample_data,
                               (char*)ctx->img_b + min_offset + off, 4);
                    }
                }
            }
        }
        
        min_offset += block_size;
    }
    
    return ctx->num_changes > 0 ? 1 : 0;
}

/* Scan for entropy regions in new image */
static int scan_entropy_regions(DiffContext *ctx, double threshold) {
    uint64_t b_size = ctx->img_b_size;
    size_t block_size = 8192;
    
    if (b_size < ENTROPY_WINDOW) return 0;
    
    /* Scan in blocks */
    for (uint64_t off = 0; off + block_size <= b_size; off += block_size) {
        if (is_high_entropy((uint8_t*)ctx->img_b + off, 
                           (size_t)(b_size - off), threshold)) {
            extract_entropy_region(ctx, off, b_size - off, threshold, 1);
        }
    }
    
    return ctx->entropy_count > 0 ? 1 : 0;
}

/* Initialize diff context */
static int diff_init(DiffContext *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->changes_cap = 64;
    ctx->changes = malloc(sizeof(ChangeRecord) * ctx->changes_cap);
    
    if (!ctx->changes) return -1;
    
    ctx->entropy_regions = malloc(sizeof(EntropyRegion) * MAX_ENTROPY_REGIONS);
    if (!ctx->entropy_regions) {
        free(ctx->changes);
        return -1;
    }
    
    return 0;
}

/* Free diff context */
static void diff_cleanup(DiffContext *ctx) {
    for (size_t i = 0; i < ctx->num_changes && ctx->changes[i].sample_data; i++) {
        free(ctx->changes[i].sample_data);
    }
    
    if (ctx->changes) free(ctx->changes);
    if (ctx->entropy_regions) free(ctx->entropy_regions);
}

/* Load a file into memory */
static int load_image(const char *path, void **out, size_t *size_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void *mem = malloc((size_t)fsize + 1);
    if (!mem) { fclose(f); return -1; }
    
    size_t nread = fread(mem, 1, (size_t)fsize, f);
    fclose(f);
    
    if ((size_t)nread != fsize) {
        free(mem);
        return -1;
    }
    
    *out = mem;
    *size_out = (size_t)fsize;
    return 0;
}

/* Load image using mmap if possible */
static int load_image_mmap(const char *path, void **out, size_t *size_out) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    
    long fsize = st.st_size;
    if (fsize <= 0 || fsize > (long)(SIZE_MAX / sizeof(void*))) {
        /* Fall back to malloc */
        return load_image(path, out, size_out);
    }
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    void *mem = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (mem == MAP_FAILED) {
        mem = malloc((size_t)fsize + 1);
        int r = read(fd, mem, fsize);
        close(fd);
        
        if ((size_t)r != fsize) {
            free(mem);
            return -1;
        }
    } else {
        /* Ensure we have a null terminator for safety */
        char *p = (char*)mem + fsize;
        while (*--p == 0);
        *(++p) = '\0';
    }
    
    *out = mem;
    *size_out = (size_t)fsize;
    return 0;
}

/* Main diff function */
int fwxray_diff(const char *img_a_path, const char *img_b_path, 
                DiffContext *ctx) {
    int r;
    
    /* Load images - prefer mmap for large files */
    if ((r = load_image_mmap(img_a_path, &ctx->img_a, &ctx->img_a_size)) < 0) {
        return r;
    }
    
    if ((r = load_image_mmap(img_b_path, &ctx->img_b, &ctx->img_b_size)) < 0) {
        free(ctx->img_a);
        ctx->img_a = NULL;
        return r;
    }
    
    /* Ensure aligned sizes for comparison */
    size_t min_len = ctx->img_a_size < ctx->img_b_size ? 
                    ctx->img_a_size : ctx->img_b_size;
    
    if (min_len == 0) {
        free(ctx->img_a);
        free(ctx->img_b);
        return -1;
    }
    
    /* Compare in blocks */
    size_t block_size = 8192;
    uint64_t min_offset = ctx->img_a_size > ctx->img_b_size ? 
                        ctx->img_a_size - block_size : 0;
    
    while (min_offset < min_len) {
        compare_regions(ctx, min_offset, 
                       (size_t)(ctx->img_a_size - min_offset),
                       (size_t)(ctx->img_b_size - min_offset));
        min_offset += block_size;
    }
    
    /* Scan for config flips */
    scan_config_flips(ctx);
    
    /* Scan for entropy regions */
    scan_entropy_regions(ctx, ENTROPY_THRESHOLD);
    
    return 0;
}

/* Print diff results to stdout */
void fwxray_print_diff(DiffContext *ctx) {
    printf("\n=== FWXRAY BINARY DIFF REPORT ===\n\n");
    
    size_t total_changes = ctx->num_changes + ctx->entropy_count;
    if (total_changes == 0) {
        printf("No significant changes detected.\n");
        return;
    }
    
    /* Summary */
    printf("--- SUMMARY ---\n");
    printf("Total change records: %zu\n", total_changes);
    printf("Entropy regions found: %zu\n\n", ctx->entropy_count);
    
    /* Breakdown by type */
    size_t new_blocks = 0, removed = 0, modified = 0, config_flips = 0;
    
    for