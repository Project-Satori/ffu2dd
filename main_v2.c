#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <io.h>
#include <direct.h>
#define fseeko _fseeki64
#define ftello _ftelli64
#define fileno _fileno
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define SECURITY_HEADER_MIN 32u
#define IMAGE_HEADER_MIN 24u
#define STORE_HEADER_SIZE 248u
#define IO_BUFFER_SIZE (1024u * 1024u)
#define MAX_LOCATIONS 4096u
#define MAX_WRITE_DESCRIPTORS 1000000u
#define MAX_PARTITIONS 16384u
#define MAX_GPT_TABLE_BYTES (64u * 1024u * 1024u)
#define GPT_MIN_HEADER_SIZE 92u
#define GPT_MIN_ENTRY_SIZE 128u
#define GPT_MAX_ENTRY_SIZE 4096u

typedef struct {
    uint32_t method;
    uint32_t block_index;
} DiskLocation;

typedef struct {
    uint32_t location_count;
    uint32_t block_count;
    DiskLocation *locations;
    uint64_t data_offset;
    uint64_t data_size;
} WriteDescriptor;

typedef struct {
    uint32_t chunk_alignment;
    uint32_t block_size;
    uint32_t write_descriptor_count;
    uint32_t write_descriptor_length;
    uint32_t validate_descriptor_count;
    uint32_t validate_descriptor_length;
    uint32_t initial_table_index;
    uint32_t initial_table_count;
    uint32_t flash_only_table_index;
    uint32_t flash_only_table_count;
    uint32_t final_table_index;
    uint32_t final_table_count;
    uint16_t ff_major;
    uint16_t ff_minor;
    char platform[193];
    uint64_t payload_offset;
    uint64_t file_size;
    WriteDescriptor *descriptors;
} FFUInfo;

typedef struct {
    uint64_t total_blocks;
    uint64_t alternate_lba;
    uint64_t entries_lba;
    uint32_t sector_size;
    uint32_t header_size;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t entries_crc;
    int header_crc_valid;
} GPTHeader;

static uint16_t le16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t le64(const unsigned char *p) {
    return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}

static int add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (UINT64_MAX - a < b) return -1;
    *out = a + b;
    return 0;
}

static int mul_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (a && b > UINT64_MAX / a) return -1;
    *out = a * b;
    return 0;
}

static int align_up_u64(uint64_t value, uint64_t alignment, uint64_t *out) {
    uint64_t rem;
    if (!alignment) return -1;
    rem = value % alignment;
    if (!rem) {
        *out = value;
        return 0;
    }
    return add_u64(value, alignment - rem, out);
}

static int seek64(FILE *fp, uint64_t offset) {
    if (offset > (uint64_t)INT64_MAX) return -1;
    return fseeko(fp, (off_t)offset, SEEK_SET);
}

static int tell64(FILE *fp, uint64_t *offset) {
    off_t p = ftello(fp);
    if (p < 0) return -1;
    *offset = (uint64_t)p;
    return 0;
}

static int file_size(FILE *fp, uint64_t *size) {
    struct stat st;
    if (fstat(fileno(fp), &st) != 0 || st.st_size < 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

static int set_file_size(FILE *fp, uint64_t size) {
    if (size > (uint64_t)INT64_MAX) return -1;
#ifdef _WIN32
    return _chsize_s(fileno(fp), size) == 0 ? 0 : -1;
#else
    return ftruncate(fileno(fp), (off_t)size);
#endif
}

static int read_exact(FILE *fp, void *buffer, size_t size) {
    return size == 0 || fread(buffer, 1, size, fp) == size ? 0 : -1;
}

static int read_at(FILE *fp, uint64_t offset, void *buffer, size_t size) {
    if (seek64(fp, offset) != 0) return -1;
    return read_exact(fp, buffer, size);
}

static int copy_input_to_output(FILE *in, uint64_t input_offset, FILE *out,
                                uint64_t output_offset, uint64_t length,
                                uint64_t output_limit) {
    unsigned char *buffer;
    uint64_t input_end, output_end;
    if (add_u64(input_offset, length, &input_end) != 0) return -1;
    if (add_u64(output_offset, length, &output_end) != 0) return -1;
    if (input_end > UINT64_MAX - 1 || (output_limit && output_end > output_limit)) return -1;
    if (seek64(in, input_offset) != 0 || seek64(out, output_offset) != 0) return -1;
    buffer = (unsigned char *)malloc(IO_BUFFER_SIZE);
    if (!buffer) return -1;
    while (length) {
        size_t n = length > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : (size_t)length;
        if (fread(buffer, 1, n, in) != n || fwrite(buffer, 1, n, out) != n) {
            free(buffer);
            return -1;
        }
        length -= n;
    }
    free(buffer);
    return 0;
}

static void free_info(FFUInfo *info) {
    uint32_t i;
    if (!info) return;
    if (info->descriptors) {
        for (i = 0; i < info->write_descriptor_count; ++i)
            free(info->descriptors[i].locations);
        free(info->descriptors);
    }
    memset(info, 0, sizeof(*info));
}

static int parse_ffu(FILE *in, FFUInfo *info) {
    unsigned char h[STORE_HEADER_SIZE];
    unsigned char sec[SECURITY_HEADER_MIN];
    unsigned char img[IMAGE_HEADER_MIN];
    uint64_t file_len, security_region, image_start, image_region;
    uint64_t store_start, desc_start, desc_end, store_region_end;
    uint64_t cursor, payload_cursor = 0;
    uint32_t sec_cb, catalog_size, hash_size, chunk_kb;
    uint32_t image_cb, manifest_len;
    uint32_t i;

    memset(info, 0, sizeof(*info));
    if (file_size(in, &file_len) != 0 || file_len < sizeof(sec)) {
        fprintf(stderr, "error: cannot determine input size or file is too small\n");
        return -1;
    }
    info->file_size = file_len;
    if (read_at(in, 0, sec, sizeof(sec)) != 0) {
        fprintf(stderr, "error: unable to read FFU security header\n");
        return -1;
    }
    if (memcmp(sec + 4, "SignedImage ", 12) != 0) {
        fprintf(stderr, "error: invalid FFU signature (expected 'SignedImage ')\n");
        return -1;
    }

    sec_cb = le32(sec + 0);
    chunk_kb = le32(sec + 16);
    catalog_size = le32(sec + 24);
    hash_size = le32(sec + 28);
    if (sec_cb < SECURITY_HEADER_MIN || chunk_kb == 0 || chunk_kb > (1024u * 1024u)) {
        fprintf(stderr, "error: invalid security header size or chunk alignment\n");
        return -1;
    }
    info->chunk_alignment = chunk_kb * 1024u;
    {
        uint64_t total;
        if (add_u64(sec_cb, catalog_size, &total) != 0 ||
            add_u64(total, hash_size, &total) != 0 ||
            align_up_u64(total, info->chunk_alignment, &security_region) != 0 ||
            security_region > file_len) {
            fprintf(stderr, "error: security header/catalog/hash region exceeds file\n");
            return -1;
        }
    }

    image_start = security_region;
    if (read_at(in, image_start, img, sizeof(img)) != 0) {
        fprintf(stderr,
                "error: truncated FFU image header at offset 0x%" PRIx64
                " (file size 0x%" PRIx64 ")\n",
                image_start, file_len);
        return -1;
    }
    /* The fixed-width field is 12 bytes, but the visible signature text
       "ImageFlash " is 11 bytes. Do not require a particular value for the
       twelfth padding byte; some producers do not NUL-terminate it. */
    if (memcmp(img + 4, "ImageFlash ", 11) != 0) {
        unsigned int j;
        fprintf(stderr,
                "error: ImageFlash signature not found at computed offset "
                "0x%" PRIx64 " (security header=%u, catalog=%u, hash=%u, "
                "chunk alignment=%u). Bytes at candidate: ",
                image_start, sec_cb, catalog_size, hash_size,
                info->chunk_alignment);
        for (j = 0; j < 12; ++j) fprintf(stderr, "%02X%s", img[4 + j], j == 11 ? "" : " ");
        fputc('\n', stderr);
        return -1;
    }
    image_cb = le32(img + 0);
    manifest_len = le32(img + 16);
    if (image_cb < IMAGE_HEADER_MIN) {
        fprintf(stderr, "error: unsupported/invalid image header size (%u)\n", image_cb);
        return -1;
    }
    {
        uint64_t image_bytes;
        if (add_u64(image_cb, manifest_len, &image_bytes) != 0 ||
            align_up_u64(image_bytes, info->chunk_alignment, &image_region) != 0 ||
            add_u64(image_start, image_region, &store_start) != 0 ||
            store_start > file_len || file_len - store_start < STORE_HEADER_SIZE) {
            fprintf(stderr, "error: image header/manifest region exceeds file\n");
            return -1;
        }
    }

    if (read_at(in, store_start, h, STORE_HEADER_SIZE) != 0) {
        fprintf(stderr, "error: unable to read FFU store header\n");
        return -1;
    }
    info->ff_major = le16(h + 8);
    info->ff_minor = le16(h + 10);
    memcpy(info->platform, h + 12, 192);
    info->platform[192] = '\0';
    info->block_size = le32(h + 204);
    info->write_descriptor_count = le32(h + 208);
    info->write_descriptor_length = le32(h + 212);
    info->validate_descriptor_count = le32(h + 216);
    info->validate_descriptor_length = le32(h + 220);
    info->initial_table_index = le32(h + 224);
    info->initial_table_count = le32(h + 228);
    info->flash_only_table_index = le32(h + 232);
    info->flash_only_table_count = le32(h + 236);
    info->final_table_index = le32(h + 240);
    info->final_table_count = le32(h + 244);

    if (info->block_size < 512 || info->block_size > (1024u * 1024u) ||
        (info->block_size & (info->block_size - 1u)) != 0) {
        fprintf(stderr, "error: unsupported image block size: %u\n", info->block_size);
        return -1;
    }
    if (info->write_descriptor_count == 0 ||
        info->write_descriptor_count > MAX_WRITE_DESCRIPTORS ||
        info->write_descriptor_length < (uint64_t)info->write_descriptor_count * 16u) {
        fprintf(stderr, "error: invalid write descriptor count/length: %u / %u\n",
                info->write_descriptor_count, info->write_descriptor_length);
        return -1;
    }
    if (add_u64(store_start, STORE_HEADER_SIZE, &desc_start) != 0 ||
        add_u64(desc_start, info->validate_descriptor_length, &desc_start) != 0 ||
        add_u64(desc_start, info->write_descriptor_length, &desc_end) != 0 ||
        desc_end > file_len ||
        add_u64(store_start, STORE_HEADER_SIZE, &store_region_end) != 0 ||
        add_u64(store_region_end, info->validate_descriptor_length, &store_region_end) != 0 ||
        add_u64(store_region_end, info->write_descriptor_length, &store_region_end) != 0 ||
        align_up_u64(store_region_end, info->chunk_alignment, &info->payload_offset) != 0 ||
        info->payload_offset > file_len) {
        fprintf(stderr, "error: FFU descriptor area exceeds file\n");
        return -1;
    }

    /* This implementation intentionally handles the classic, uncompressed,
       single-store FFU descriptor layout. Unexpected per-entry fields (such
       as compression metadata) are rejected rather than misparsed. */
    info->descriptors = (WriteDescriptor *)calloc(info->write_descriptor_count,
                                                   sizeof(*info->descriptors));
    if (!info->descriptors) {
        fprintf(stderr, "error: out of memory allocating write descriptors\n");
        return -1;
    }
    cursor = desc_start;
    for (i = 0; i < info->write_descriptor_count; ++i) {
        unsigned char dh[8];
        uint32_t j;
        uint64_t locations_bytes, next;
        WriteDescriptor *d = &info->descriptors[i];
        if (cursor > desc_end || desc_end - cursor < sizeof(dh) ||
            read_at(in, cursor, dh, sizeof(dh)) != 0) {
            fprintf(stderr, "error: truncated write descriptor %u\n", i);
            return -1;
        }
        d->location_count = le32(dh + 0);
        d->block_count = le32(dh + 4);
        if (d->location_count == 0 || d->location_count > MAX_LOCATIONS || d->block_count == 0) {
            fprintf(stderr, "error: invalid descriptor %u (locations=%u blocks=%u)\n",
                    i, d->location_count, d->block_count);
            return -1;
        }
        if (mul_u64(d->location_count, 8, &locations_bytes) != 0 ||
            add_u64(cursor, 8, &next) != 0 ||
            add_u64(next, locations_bytes, &next) != 0 || next > desc_end) {
            fprintf(stderr, "error: descriptor %u location table exceeds descriptor area\n", i);
            return -1;
        }
        d->locations = (DiskLocation *)calloc(d->location_count, sizeof(*d->locations));
        if (!d->locations) {
            fprintf(stderr, "error: out of memory allocating descriptor locations\n");
            return -1;
        }
        for (j = 0; j < d->location_count; ++j) {
            unsigned char loc[8];
            if (read_at(in, cursor + 8u + (uint64_t)j * 8u, loc, sizeof(loc)) != 0) {
                fprintf(stderr, "error: unable to read descriptor %u location %u\n", i, j);
                return -1;
            }
            d->locations[j].method = le32(loc + 0);
            d->locations[j].block_index = le32(loc + 4);
            if (d->locations[j].method > 2) {
                fprintf(stderr, "error: descriptor %u uses unsupported disk access method %u\n",
                        i, d->locations[j].method);
                return -1;
            }
        }
        cursor = next;
        if (mul_u64(d->block_count, info->block_size, &d->data_size) != 0 ||
            add_u64(info->payload_offset, payload_cursor, &d->data_offset) != 0 ||
            add_u64(payload_cursor, d->data_size, &payload_cursor) != 0) {
            fprintf(stderr, "error: descriptor %u data size overflows\n", i);
            return -1;
        }
    }
    if (cursor != desc_end) {
        fprintf(stderr,
                "error: write descriptor layout has %" PRIu64
                " unexplained trailing bytes (compressed/other FFU variants may be unsupported)\n",
                desc_end - cursor);
        return -1;
    }
    {
        uint64_t payload_end = 0;
        if (add_u64(info->payload_offset, payload_cursor, &payload_end) != 0) {
            fprintf(stderr, "error: FFU payload size overflows 64-bit offsets\n");
            return -1;
        }
        if (payload_end > file_len) {
            fprintf(stderr, "error: FFU payload is truncated (needs end at 0x%" PRIx64
                            ", file ends at 0x%" PRIx64 ")\n", payload_end, file_len);
            return -1;
        }
    }

    printf("FFU platform : %.192s\n", info->platform);
    printf("FFU version  : %u.%u\n", info->ff_major, info->ff_minor);
    printf("Block size   : %u bytes\n", info->block_size);
    printf("Descriptors  : %u\n", info->write_descriptor_count);
    printf("GPT payloads : initial=%u+%u flash-only=%u+%u final=%u+%u blocks\n",
           info->initial_table_index, info->initial_table_count,
           info->flash_only_table_index, info->flash_only_table_count,
           info->final_table_index, info->final_table_count);
    printf("Payload at   : 0x%" PRIx64 "\n", info->payload_offset);
    return 0;
}

static int offset_for_location(FILE *out, const DiskLocation *loc,
                               uint32_t block_size, uint64_t disk_bytes,
                               uint64_t *target_offset) {
    uint64_t curr;
    int64_t signed_index = (int32_t)loc->block_index;
    int64_t delta;
    switch (loc->method) {
    case 0: /* DISK_BEGIN: absolute block index */
        if (mul_u64(loc->block_index, block_size, target_offset) != 0) return -1;
        if (disk_bytes && *target_offset > disk_bytes) return -1;
        return 0;
    case 1: /* DISK_SEQ: SetFilePointer-style offset from current position */
        if (tell64(out, &curr) != 0) return -1;
        if (signed_index > INT64_MAX / (int64_t)block_size ||
            signed_index < INT64_MIN / (int64_t)block_size) return -1;
        delta = signed_index * (int64_t)block_size;
        if (delta < 0 && curr < (uint64_t)(-delta)) return -1;
        if (delta > 0 && curr > UINT64_MAX - (uint64_t)delta) return -1;
        *target_offset = delta < 0 ? curr - (uint64_t)(-delta) : curr + (uint64_t)delta;
        return 0;
    case 2: /* DISK_END: resolved after reading the primary GPT */
        if (!disk_bytes) return 1;
        if (signed_index > INT64_MAX / (int64_t)block_size ||
            signed_index < INT64_MIN / (int64_t)block_size) return -1;
        delta = signed_index * (int64_t)block_size;
        if (delta < 0 && disk_bytes < (uint64_t)(-delta)) return -1;
        if (delta > 0 && disk_bytes > UINT64_MAX - (uint64_t)delta) return -1;
        *target_offset = delta < 0 ? disk_bytes - (uint64_t)(-delta) : disk_bytes + (uint64_t)delta;
        return 0;
    default:
        return -1;
    }
}

static int write_descriptor(FILE *in, FILE *out, const WriteDescriptor *d,
                             uint32_t block_size, uint64_t disk_bytes,
                             int allow_end, uint64_t *actual_end) {
    uint32_t i;
    for (i = 0; i < d->location_count; ++i) {
        uint64_t out_offset, out_end;
        int r;
        const DiskLocation *loc = &d->locations[i];
        if (loc->method == 2 && !allow_end) return 1;
        r = offset_for_location(out, loc, block_size, disk_bytes, &out_offset);
        if (r != 0) return r;
        if (add_u64(out_offset, d->data_size, &out_end) != 0 ||
            (disk_bytes && out_end > disk_bytes)) {
            fprintf(stderr,
                    "error: descriptor destination range exceeds disk bounds: "
                    "method=%u block_index=0x%08" PRIx32 " (%" PRId32 "), "
                    "target=0x%" PRIx64 ", data=0x%" PRIx64 ", "
                    "end=0x%" PRIx64 ", disk=0x%" PRIx64 ", "
                    "descriptor_blocks=%" PRIu32 " block_size=%" PRIu32 "\n",
                    loc->method, loc->block_index, (int32_t)loc->block_index,
                    out_offset, d->data_size,
                    add_u64(out_offset, d->data_size, &out_end) == 0 ? out_end : UINT64_MAX,
                    disk_bytes, d->block_count, block_size);
            return -1;
        }
        if (copy_input_to_output(in, d->data_offset, out, out_offset, d->data_size,
                                 disk_bytes) != 0) {
            fprintf(stderr, "error: failed to copy payload for destination block 0x%" PRIx64 "\n",
                    out_offset / block_size);
            return -1;
        }
        if (actual_end && out_end > *actual_end) *actual_end = out_end;
    }
    return 0;
}

typedef struct {
    int known;
    uint64_t offset;
} ProbeCursor;

static int apply_signed_delta(uint64_t base, int64_t delta, uint64_t *result) {
    if (delta < 0) {
        /* Avoid negating INT64_MIN directly. */
        uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1u;
        if (base < magnitude) return -1;
        *result = base - magnitude;
    } else {
        if (base > UINT64_MAX - (uint64_t)delta) return -1;
        *result = base + (uint64_t)delta;
    }
    return 0;
}

/*
 * First pass: write only destinations that can be resolved without knowing
 * the disk size. DISK_END locations are skipped, but later descriptors are
 * still visited because FFU descriptor order follows payload order, not disk
 * LBA order. A DISK_SEQ location after an unresolved DISK_END is also skipped
 * until a DISK_BEGIN location re-establishes a known cursor. This pass is only
 * used to discover the final primary GPT and disk size; the image is cleared
 * and replayed in full after disk_bytes has been determined.
 */
static int probe_write_descriptor(FILE *in, FILE *out, const WriteDescriptor *d,
                                  uint32_t block_size, ProbeCursor *cursor,
                                  int *skipped_unresolved) {
    uint32_t i;

    for (i = 0; i < d->location_count; ++i) {
        const DiskLocation *loc = &d->locations[i];
        uint64_t target = 0, target_end;
        int target_known = 1;

        if (loc->method == 0) { /* DISK_BEGIN */
            if (mul_u64(loc->block_index, block_size, &target) != 0) return -1;
        } else if (loc->method == 1) { /* DISK_SEQ */
            int64_t index = (int32_t)loc->block_index;
            int64_t delta;
            if (index > INT64_MAX / (int64_t)block_size ||
                index < INT64_MIN / (int64_t)block_size) return -1;
            delta = index * (int64_t)block_size;
            if (!cursor->known) {
                target_known = 0;
                *skipped_unresolved = 1;
            } else if (apply_signed_delta(cursor->offset, delta, &target) != 0) {
                return -1;
            }
        } else if (loc->method == 2) { /* DISK_END */
            target_known = 0;
            cursor->known = 0;
            *skipped_unresolved = 1;
        } else {
            return -1;
        }

        if (!target_known) continue;
        if (add_u64(target, d->data_size, &target_end) != 0) return -1;
        if (copy_input_to_output(in, d->data_offset, out, target,
                                 d->data_size, 0) != 0) {
            fprintf(stderr,
                    "error: failed writing probe data for destination offset 0x%" PRIx64 "\n",
                    target);
            return -1;
        }
        cursor->known = 1;
        cursor->offset = target_end;
    }
    return 0;
}

static uint32_t crc32_ieee(const unsigned char *data, size_t length) {
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0; i < length; ++i) {
        unsigned int bit;
        crc ^= data[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}

static int read_gpt_header(FILE *disk, GPTHeader *gpt, int print_errors) {
    static const uint32_t candidates[] = {512u, 4096u, 1024u, 2048u};
    unsigned char *block = NULL;
    uint32_t sector_size = 0, i;
    uint32_t stored_crc, computed_crc;
    int found = 0;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        uint64_t offset;
        sector_size = candidates[i];
        block = (unsigned char *)malloc(sector_size);
        if (!block) return -1;
        if (mul_u64(1, sector_size, &offset) == 0 &&
            read_at(disk, offset, block, sector_size) == 0 &&
            memcmp(block, "EFI PART", 8) == 0) {
            found = 1;
            break;
        }
        free(block);
        block = NULL;
    }
    if (!found) {
        if (print_errors) fprintf(stderr, "error: no GPT signature at LBA 1 (tried 512/1024/2048/4096-byte sectors)\n");
        return -1;
    }

    memset(gpt, 0, sizeof(*gpt));
    gpt->sector_size = sector_size;
    gpt->header_size = le32(block + 12);
    stored_crc = le32(block + 16);
    gpt->alternate_lba = le64(block + 32);
    gpt->entries_lba = le64(block + 72);
    gpt->entry_count = le32(block + 80);
    gpt->entry_size = le32(block + 84);
    gpt->entries_crc = le32(block + 88);
    if (gpt->header_size < GPT_MIN_HEADER_SIZE || gpt->header_size > sector_size ||
        le64(block + 24) != 1 || gpt->alternate_lba < 2) {
        free(block);
        if (print_errors) fprintf(stderr, "error: malformed primary GPT header\n");
        return -1;
    }
    {
        unsigned char *copy = (unsigned char *)malloc(gpt->header_size);
        if (copy) {
            memcpy(copy, block, gpt->header_size);
            memset(copy + 16, 0, 4);
            computed_crc = crc32_ieee(copy, gpt->header_size);
            gpt->header_crc_valid = (computed_crc == stored_crc);
            if (!gpt->header_crc_valid)
                fprintf(stderr, "warning: GPT header CRC mismatch (stored %08x, computed %08x)\n",
                        stored_crc, computed_crc);
            free(copy);
        } else {
            gpt->header_crc_valid = 0;
        }
    }
    if (gpt->alternate_lba == UINT64_MAX ||
        add_u64(gpt->alternate_lba, 1, &gpt->total_blocks) != 0) {
        free(block);
        if (print_errors) fprintf(stderr, "error: invalid GPT alternate LBA\n");
        return -1;
    }
    free(block);
    return 0;
}

static int parse_gpt_header_sector(const unsigned char *sector, uint32_t sector_size,
                                   GPTHeader *gpt) {
    unsigned char copy[GPT_MAX_ENTRY_SIZE];
    uint32_t header_size, stored_crc, computed_crc;

    if (sector_size < GPT_MIN_HEADER_SIZE || sector_size > sizeof(copy) ||
        memcmp(sector, "EFI PART", 8) != 0) return -1;
    header_size = le32(sector + 12);
    if (header_size < GPT_MIN_HEADER_SIZE || header_size > sector_size ||
        le64(sector + 24) != 1 || le64(sector + 32) < 2) return -1;

    memcpy(copy, sector, header_size);
    stored_crc = le32(copy + 16);
    memset(copy + 16, 0, 4);
    computed_crc = crc32_ieee(copy, header_size);
    if (computed_crc != stored_crc) return -1;

    memset(gpt, 0, sizeof(*gpt));
    gpt->sector_size = sector_size;
    gpt->header_size = header_size;
    gpt->alternate_lba = le64(sector + 32);
    gpt->entries_lba = le64(sector + 72);
    gpt->entry_count = le32(sector + 80);
    gpt->entry_size = le32(sector + 84);
    gpt->entries_crc = le32(sector + 88);
    if (add_u64(gpt->alternate_lba, 1, &gpt->total_blocks) != 0) return -1;
    gpt->header_crc_valid = 1;
    return 0;
}

/*
 * The Store Header records the payload block range containing the final GPT.
 * Prefer that authoritative table over a GPT left in the probe image: the
 * probe may contain an intentionally transitional/invalid GPT if writes using
 * DISK_END or DISK_SEQ could not be resolved yet.
 */
static int read_final_gpt_from_payload(FILE *in, const FFUInfo *info,
                                       GPTHeader *gpt, uint64_t *payload_block_out) {
    static const uint32_t candidates[] = {512u, 4096u, 1024u, 2048u};
    unsigned char *block = NULL;
    uint64_t total_payload_blocks = 0, wanted_end;
    uint64_t descriptor_first_block = 0;
    uint32_t i;

    if (info->final_table_count == 0 ||
        add_u64(info->final_table_index, info->final_table_count, &wanted_end) != 0)
        return -1;
    for (i = 0; i < info->write_descriptor_count; ++i) {
        if (add_u64(total_payload_blocks, info->descriptors[i].block_count,
                    &total_payload_blocks) != 0) return -1;
    }
    if (wanted_end > total_payload_blocks) return -1;

    block = (unsigned char *)malloc(info->block_size);
    if (!block) return -1;
    for (i = 0; i < info->write_descriptor_count; ++i) {
        const WriteDescriptor *d = &info->descriptors[i];
        uint64_t descriptor_end, first, last, payload_index;
        if (add_u64(descriptor_first_block, d->block_count, &descriptor_end) != 0) {
            free(block);
            return -1;
        }
        first = descriptor_first_block > info->final_table_index
                    ? descriptor_first_block : info->final_table_index;
        last = descriptor_end < wanted_end ? descriptor_end : wanted_end;
        for (payload_index = first; payload_index < last; ++payload_index) {
            uint64_t file_offset;
            size_t c;
            if (mul_u64(payload_index - descriptor_first_block,
                        info->block_size, &file_offset) != 0 ||
                add_u64(d->data_offset, file_offset, &file_offset) != 0 ||
                read_at(in, file_offset, block, info->block_size) != 0) {
                free(block);
                return -1;
            }
            for (c = 0; c < sizeof(candidates) / sizeof(candidates[0]); ++c) {
                uint32_t sector_size = candidates[c];
                if ((uint64_t)sector_size + GPT_MIN_HEADER_SIZE > info->block_size)
                    continue;
                if (parse_gpt_header_sector(block + sector_size, sector_size, gpt) == 0) {
                    if (payload_block_out) *payload_block_out = payload_index;
                    free(block);
                    return 0;
                }
            }
        }
        descriptor_first_block = descriptor_end;
        if (descriptor_first_block >= wanted_end) break;
    }
    free(block);
    return -1;
}

static void guid_to_string(const unsigned char *g, char out[37]) {
    (void)snprintf(out, 37,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
        g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

static void partition_name(const unsigned char *entry, char out[145]) {
    size_t i, n = 0;
    for (i = 0; i < 72 && n < 143; i += 2) {
        uint16_t c = le16(entry + 56 + i);
        if (c == 0) break;
        if (c >= 0x20 && c <= 0x7e && c != '/' && c != '\\' && c != ':' &&
            c != '\t' && c != '\r' && c != '\n')
            out[n++] = (char)c;
        else
            out[n++] = '_';
    }
    while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '.')) --n;
    out[n] = '\0';
    if (n == 0) strcpy(out, "unnamed");
    if (strcmp(out, ".") == 0 || strcmp(out, "..") == 0) strcpy(out, "unnamed");
}

static char *join_path(const char *dir, const char *name) {
    size_t a = strlen(dir), b = strlen(name);
    char *p = (char *)malloc(a + b + 2);
    if (!p) return NULL;
    memcpy(p, dir, a);
    if (a && dir[a - 1] != '/' && dir[a - 1] != '\\') p[a++] = '/';
    memcpy(p + a, name, b + 1);
    return p;
}

static int make_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "error: split path exists and is not a directory: %s\n", path);
        return -1;
    }
    if (mkdir(path, 0775) != 0 && errno != EEXIST) {
        fprintf(stderr, "error: cannot create directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: split output path is not a directory: %s\n", path);
        return -1;
    }
    return 0;
}

static int split_partitions(FILE *disk, const char *out_dir) {
    GPTHeader gpt;
    unsigned char *entries = NULL;
    uint64_t entry_bytes, entries_offset, entries_end, disk_bytes, disk_file_size;
    FILE *manifest = NULL;
    char *manifest_path = NULL;
    uint32_t i, exported = 0;
    int result = -1;

    if (read_gpt_header(disk, &gpt, 1) != 0) return -1;
    if (gpt.entry_count == 0 || gpt.entry_count > MAX_PARTITIONS ||
        gpt.entry_size < GPT_MIN_ENTRY_SIZE || gpt.entry_size > GPT_MAX_ENTRY_SIZE ||
        (gpt.entry_size & 7u) != 0) {
        fprintf(stderr, "error: unsupported GPT entry table dimensions (%u x %u)\n",
                gpt.entry_count, gpt.entry_size);
        return -1;
    }
    if (mul_u64(gpt.entry_count, gpt.entry_size, &entry_bytes) != 0 ||
        entry_bytes > MAX_GPT_TABLE_BYTES ||
        mul_u64(gpt.entries_lba, gpt.sector_size, &entries_offset) != 0 ||
        add_u64(entries_offset, entry_bytes, &entries_end) != 0 ||
        mul_u64(gpt.total_blocks, gpt.sector_size, &disk_bytes) != 0 ||
        entries_end > disk_bytes || file_size(disk, &disk_file_size) != 0 ||
        disk_file_size < disk_bytes) {
        fprintf(stderr, "error: GPT table or declared disk size is outside the reconstructed image\n");
        return -1;
    }
    entries = (unsigned char *)malloc((size_t)entry_bytes);
    if (!entries) {
        fprintf(stderr, "error: out of memory allocating GPT entries\n");
        return -1;
    }
    if (read_at(disk, entries_offset, entries, (size_t)entry_bytes) != 0) {
        fprintf(stderr, "error: unable to read GPT partition entry array\n");
        goto done;
    }
    if (crc32_ieee(entries, (size_t)entry_bytes) != gpt.entries_crc)
        fprintf(stderr, "warning: GPT partition entry array CRC mismatch; attempting best-effort split\n");

    if (make_directory(out_dir) != 0) goto done;
    manifest_path = join_path(out_dir, "partitions.tsv");
    if (!manifest_path) {
        fprintf(stderr, "error: out of memory creating manifest path\n");
        goto done;
    }
    manifest = fopen(manifest_path, "wb");
    if (!manifest) {
        fprintf(stderr, "error: cannot create %s: %s\n", manifest_path, strerror(errno));
        goto done;
    }
    fprintf(manifest, "index\tname\ttype_guid\tunique_guid\tfirst_lba\tlast_lba\tsectors\tbytes\tfile\n");

    for (i = 0; i < gpt.entry_count; ++i) {
        const unsigned char *e = entries + (size_t)i * gpt.entry_size;
        unsigned char zero_guid[16] = {0};
        uint64_t first_lba, last_lba, sectors, offset, length, end;
        char name[145], type_guid[37], unique_guid[37], output_name[200];
        char *output_path;
        FILE *part;
        if (memcmp(e, zero_guid, sizeof(zero_guid)) == 0) continue;
        first_lba = le64(e + 32);
        last_lba = le64(e + 40);
        if (last_lba < first_lba || last_lba >= gpt.total_blocks) {
            fprintf(stderr, "error: GPT partition entry %u has invalid LBA range (%" PRIu64 "..%" PRIu64 ")\n",
                    i + 1, first_lba, last_lba);
            goto done;
        }
        sectors = last_lba - first_lba + 1;
        if (mul_u64(first_lba, gpt.sector_size, &offset) != 0 ||
            mul_u64(sectors, gpt.sector_size, &length) != 0 ||
            add_u64(offset, length, &end) != 0 || end > disk_bytes) {
            fprintf(stderr, "error: partition %u byte range overflows disk bounds\n", i + 1);
            goto done;
        }
        partition_name(e, name);
        guid_to_string(e, type_guid);
        guid_to_string(e + 16, unique_guid);
        (void)snprintf(output_name, sizeof(output_name), "%03u-%s.img", i + 1, name);
        output_path = join_path(out_dir, output_name);
        if (!output_path) {
            fprintf(stderr, "error: out of memory creating partition path\n");
            goto done;
        }
        part = fopen(output_path, "wb");
        if (!part) {
            fprintf(stderr, "error: cannot create %s: %s\n", output_path, strerror(errno));
            free(output_path);
            goto done;
        }
        if (seek64(disk, offset) != 0) {
            fclose(part);
            free(output_path);
            fprintf(stderr, "error: cannot seek to partition %s\n", name);
            goto done;
        }
        {
            unsigned char *buf = (unsigned char *)malloc(IO_BUFFER_SIZE);
            uint64_t remaining = length;
            int copy_ok = buf != NULL;
            while (copy_ok && remaining) {
                size_t n = remaining > IO_BUFFER_SIZE ? IO_BUFFER_SIZE : (size_t)remaining;
                if (fread(buf, 1, n, disk) != n || fwrite(buf, 1, n, part) != n) {
                    copy_ok = 0;
                    break;
                }
                remaining -= n;
            }
            free(buf);
            if (!copy_ok) {
                fclose(part);
                free(output_path);
                fprintf(stderr, "error: failed while exporting partition %s\n", name);
                goto done;
            }
        }
        if (fclose(part) != 0) {
            free(output_path);
            fprintf(stderr, "error: failed to close partition file for %s\n", name);
            goto done;
        }
        fprintf(manifest, "%u\t%s\t%s\t%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%s\n",
                i + 1, name, type_guid, unique_guid, first_lba, last_lba,
                sectors, length, output_name);
        printf("partition %-20s LBA %" PRIu64 "..%" PRIu64 " (%" PRIu64 " bytes) -> %s\n",
               name, first_lba, last_lba, length, output_path);
        free(output_path);
        ++exported;
    }
    if (exported == 0) {
        fprintf(stderr, "warning: GPT was valid but no used partition entries were found\n");
    }
    printf("Exported %u partitions; manifest: %s\n", exported, manifest_path);
    result = 0;

done:
    if (manifest && fclose(manifest) != 0 && result == 0) result = -1;
    free(manifest_path);
    free(entries);
    return result;
}

static int convert_ffu(FILE *in, FILE *out, const FFUInfo *info,
                       int do_split, const char *split_dir) {
    uint32_t i;
    uint64_t disk_bytes = 0, current_size = 0;
    GPTHeader gpt, final_gpt;
    ProbeCursor cursor = { 1, 0 };
    int skipped_unresolved = 0;

    /* Pass 1: best-effort reconstruction of destinations not depending on
       the unknown end of disk. Do not stop at the first DISK_END descriptor. */
    for (i = 0; i < info->write_descriptor_count; ++i) {
        if (probe_write_descriptor(in, out, &info->descriptors[i],
                                   info->block_size, &cursor,
                                   &skipped_unresolved) != 0) {
            fprintf(stderr, "error: failed probing descriptor %u\n", i);
            return -1;
        }
    }
    if (fflush(out) != 0) {
        fprintf(stderr, "error: failed flushing probe image\n");
        return -1;
    }

    {
        uint64_t final_gpt_payload_block = 0;
        GPTHeader payload_gpt;
        if (read_final_gpt_from_payload(in, info, &payload_gpt,
                                        &final_gpt_payload_block) == 0) {
            gpt = payload_gpt;
            printf("Disk size source: Store Header final-GPT payload block %" PRIu64
                   " (CRC-validated)\n", final_gpt_payload_block);
        } else {
            if (read_gpt_header(out, &gpt, 0) != 0 || !gpt.header_crc_valid) {
                fprintf(stderr,
                        "error: cannot determine disk size safely: Store Header final-GPT payload "
                        "could not be parsed, and probe image has no CRC-valid primary GPT%s\n",
                        skipped_unresolved ? " (some DISK_END/DISK_SEQ writes were skipped)" : "");
                return -1;
            }
            printf("Disk size source: CRC-validated primary GPT in probe image\n");
        }
    }
    if (mul_u64(gpt.total_blocks, gpt.sector_size, &disk_bytes) != 0 ||
        disk_bytes == 0 || file_size(out, &current_size) != 0) {
        fprintf(stderr, "error: GPT-declared disk size is invalid or probe output size unavailable\n");
        return -1;
    }

    if (current_size > disk_bytes) {
        fprintf(stderr,
                "warning: probe image extent 0x%" PRIx64 " exceeds GPT disk size 0x%" PRIx64
                "; probe may include unresolved/transitional writes; final replay will enforce GPT bounds\n",
                current_size, disk_bytes);
    }
    printf("GPT: sector=%u alternate_lba=%" PRIu64 " total_blocks=%" PRIu64
           " header_crc=%s\n",
           gpt.sector_size, gpt.alternate_lba, gpt.total_blocks,
           gpt.header_crc_valid ? "valid" : "INVALID/unchecked");
    printf("Reconstructed disk size: %" PRIu64 " bytes (sector size %u; FFU block size %u)\n",
           disk_bytes, gpt.sector_size, info->block_size);

    /* Pass 2: discard the incomplete probe and replay every descriptor in its
       original order, now that DISK_END can be resolved exactly. This also
       restores the intended overwrite order between initial/final GPT blocks. */
    if (set_file_size(out, 0) != 0 || set_file_size(out, disk_bytes) != 0 ||
        seek64(out, 0) != 0) {
        fprintf(stderr, "error: unable to initialize final disk image\n");
        return -1;
    }
    for (i = 0; i < info->write_descriptor_count; ++i) {
        if (write_descriptor(in, out, &info->descriptors[i], info->block_size,
                             disk_bytes, 1, NULL) != 0) {
            fprintf(stderr,
                    "error: failed replaying descriptor %u (locations=%" PRIu32
                    ", blocks=%" PRIu32 ", payload=0x%" PRIx64
                    "+0x%" PRIx64 ")\n",
                    i, info->descriptors[i].location_count,
                    info->descriptors[i].block_count,
                    info->descriptors[i].data_offset,
                    info->descriptors[i].data_size);
            return -1;
        }
    }
    if (fflush(out) != 0) {
        fprintf(stderr, "error: failed flushing reconstructed image\n");
        return -1;
    }

    /* Validate the result after applying the full ordered descriptor stream. */
    if (read_gpt_header(out, &final_gpt, 1) != 0 ||
        !final_gpt.header_crc_valid ||
        final_gpt.total_blocks != gpt.total_blocks ||
        final_gpt.sector_size != gpt.sector_size ||
        set_file_size(out, disk_bytes) != 0) {
        fprintf(stderr, "error: final replay did not preserve a CRC-valid primary GPT with the discovered disk size\n");
        return -1;
    }
    if (do_split) {
        if (split_partitions(out, split_dir) != 0) return -1;
    }
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
        "Usage:\n"
        "  %s input.ffu output.dd\n"
        "  %s input.ffu output.dd --split output-directory\n\n"
        "The second form also exports every used GPT partition to a separate .img\n"
        "file and writes partitions.tsv. The raw disk image is kept as output.dd.\n"
        "Supported here: classic, uncompressed, single-store FFU with GPT.\n",
        program, program);
}

int main(int argc, char **argv) {
    const char *input_path, *output_path, *split_dir = NULL;
    FILE *in = NULL, *out = NULL;
    FFUInfo info;
    int do_split = 0, status = EXIT_FAILURE;
    memset(&info, 0, sizeof(info));

    if (argc == 5 && strcmp(argv[3], "--split") == 0) {
        do_split = 1;
        split_dir = argv[4];
    } else if (argc != 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    input_path = argv[1];
    output_path = argv[2];
    if (strcmp(input_path, output_path) == 0) {
        fprintf(stderr, "error: input and output paths must differ\n");
        return EXIT_FAILURE;
    }

    in = fopen(input_path, "rb");
    if (!in) {
        fprintf(stderr, "error: cannot open input %s: %s\n", input_path, strerror(errno));
        goto done;
    }
    {
        struct stat in_stat, out_stat;
        if (fstat(fileno(in), &in_stat) != 0) {
            fprintf(stderr, "error: cannot stat input %s\n", input_path);
            goto done;
        }
        if (stat(output_path, &out_stat) == 0 &&
            in_stat.st_dev == out_stat.st_dev && in_stat.st_ino == out_stat.st_ino) {
            fprintf(stderr, "error: output resolves to the same file as input; refusing to truncate it\n");
            goto done;
        }
    }
    if (parse_ffu(in, &info) != 0) goto done;
    out = fopen(output_path, "w+b");
    if (!out) {
        fprintf(stderr, "error: cannot create output %s: %s\n", output_path, strerror(errno));
        goto done;
    }
    printf("Reconstructing disk image: %s\n", output_path);
    if (convert_ffu(in, out, &info, do_split, split_dir) != 0) goto done;
    if (fflush(out) != 0) {
        fprintf(stderr, "error: output flush failed\n");
        goto done;
    }
    {
        uint64_t n;
        if (file_size(out, &n) == 0)
            printf("Done: %s (%" PRIu64 " bytes%s)\n", output_path, n,
                   do_split ? ", partitions exported" : "");
    }
    status = EXIT_SUCCESS;

done:
    if (out && fclose(out) != 0) {
        fprintf(stderr, "warning: closing output failed\n");
        status = EXIT_FAILURE;
    }
    if (in) fclose(in);
    free_info(&info);
    if (status != EXIT_SUCCESS && output_path) {
        fprintf(stderr, "Conversion did not complete successfully. Check the output before using it.\n");
    }
    return status;
}
