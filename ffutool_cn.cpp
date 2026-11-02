#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <vector>
#include <string>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <io.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
#else
  #include <unistd.h>
#endif

// ===================== Windows 兼容层 =====================
#ifdef _WIN32

static ssize_t pread64(int fd, void *buf, size_t count, int64_t offset) {
    int64_t saved = _lseeki64(fd, 0, SEEK_CUR);
    if (saved == -1) return -1;
    if (_lseeki64(fd, offset, SEEK_SET) == -1) {
        _lseeki64(fd, saved, SEEK_SET);
        return -1;
    }
    int ret = _read(fd, buf, (unsigned int)count);
    _lseeki64(fd, saved, SEEK_SET);
    return (ssize_t)ret;
}

static ssize_t pwrite64(int fd, const void *buf, size_t count, int64_t offset) {
    int64_t saved = _lseeki64(fd, 0, SEEK_CUR);
    if (saved == -1) return -1;
    if (_lseeki64(fd, offset, SEEK_SET) == -1) {
        _lseeki64(fd, saved, SEEK_SET);
        return -1;
    }
    int ret = _write(fd, buf, (unsigned int)count);
    _lseeki64(fd, saved, SEEK_SET);
    return (ssize_t)ret;
}

// 关键：直接收 uint64_t，走 _chsize_s 的 64 位路径，避免 off_t 32 位截断
static int ffu_truncate(int fd, uint64_t size) {
    if (size > (uint64_t)0x7FFFFFFFFFFFFFFFULL) {
        errno = EINVAL;
        return -1;
    }
    errno_t err = _chsize_s(fd, (int64_t)size);
    if (err != 0) { errno = (int)err; return -1; }
    return 0;
}

#else  // POSIX

static ssize_t pread64(int fd, void *buf, size_t count, int64_t offset) {
    return pread(fd, buf, count, (off_t)offset);
}

static ssize_t pwrite64(int fd, const void *buf, size_t count, int64_t offset) {
    return pwrite(fd, buf, count, (off_t)offset);
}

static int ffu_truncate(int fd, uint64_t size) {
    return ftruncate(fd, (off_t)size);
}

#endif

// ===================== 结构体（来自 ffu.h，packed） =====================
#pragma pack(push, 1)

struct SECURITY_HEADER {
    uint32_t cbSize;
    unsigned char signature[12];   // "SignedImage "
    uint32_t dwChunkSizeInKb;
    uint32_t dwAlgId;
    uint32_t dwCatalogSize;
    uint32_t dwHashTableSize;
};

struct IMAGE_HEADER {
    uint32_t cbSize;
    unsigned char Signature[12];   // "ImageFlash  "
    uint32_t ManifestLength;
    uint32_t dwChunkSize;
};

struct STORE_HEADER {
    uint32_t dwUpdateType;
    uint16_t MajorVersion, MinorVersion;
    uint16_t FullFlashMajorVersion, FullFlashMinorVersion;
    char     szPlatformId[192];
    uint32_t dwBlockSizeInBytes;
    uint32_t dwWriteDescriptorCount;
    uint32_t dwWriteDescriptorLength;
    uint32_t dwValidateDescriptorCount;
    uint32_t dwValidateDescriptorLength;
    uint32_t dwInitialTableIndex;
    uint32_t dwInitialTableCount;
    uint32_t dwFlashOnlyTableIndex;
    uint32_t dwFlashOnlyTableCount;
    uint32_t dwFinalTableIndex;
    uint32_t dwFinalTableCount;
};

enum DISK_ACCESS_METHOD { DISK_BEGIN = 0, DISK_SEQ = 1, DISK_END = 2 };

struct DISK_LOCATION {
    uint32_t dwDiskAccessMethod;
    uint32_t dwBlockIndex;
};

struct BLOCK_DATA_ENTRY {
    uint32_t dwLocationCount;
    uint32_t dwBlockCount;
    DISK_LOCATION rgDiskLocations[1]; // 柔性数组
};

// 最小 GPT 定义（packed 92 字节 header）
struct gpt_header_t {
    char     signature[8];       // "EFI PART"
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    unsigned char disk_guid[16];
    uint64_t partition_entry_lba;
    uint32_t num_partition_entries;
    uint32_t sizeof_partition_entry;
    uint32_t partition_entry_array_crc32;
};

struct gpt_entry_t {
    unsigned char partition_type_guid[16];
    unsigned char unique_partition_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attributes;
    char     part_name[72];      // UTF-16LE
};

#pragma pack(pop)

// ===================== 工具函数 =====================
static uint64_t GetNextStartingArea(uint64_t chunkSize, uint64_t sizeOfArea) {
    if (chunkSize == 0) return sizeOfArea;
    uint64_t rem = sizeOfArea % chunkSize;
    if (rem != 0) return sizeOfArea + (chunkSize - rem);
    return sizeOfArea;
}

static std::string utf16le_to_ascii(const char *src, size_t max_bytes) {
    std::string out;
    for (size_t i = 0; i + 1 < max_bytes; i += 2) {
        uint16_t w = (uint8_t)src[i] | ((uint8_t)src[i + 1] << 8);
        if (w == 0) break;
        out.push_back(w < 128 ? (char)w : '?');
    }
    return out;
}

// ===================== FFUImage 类 =====================
class FFUImage {
public:
    FFUImage() = default;
    ~FFUImage() { Close(); }

    int Open(const char *path);
    void Close();
    int Parse();
    int DumpRawProgram(const char *out_xml);
    int SplitAll(const char *out_dir);

private:
    int fd_ = -1;
    SECURITY_HEADER sec_{};
    IMAGE_HEADER    img_{};
    STORE_HEADER    store_{};
    std::vector<uint8_t> validation_;
    std::vector<uint8_t> block_entries_raw_;
    uint64_t payload_start_ = 0;

    gpt_header_t gpt_hdr_{};
    std::vector<gpt_entry_t> gpt_entries_;

    ssize_t Pread(void *buf, size_t n, uint64_t off) {
        return pread64(fd_, buf, n, (int64_t)off);
    }
    ssize_t Pwrite(const void *buf, size_t n, uint64_t off) {
        return pwrite64(fd_, buf, n, (int64_t)off);
    }

    const uint8_t *EntryAt(size_t index, uint32_t *loc_count_out) const;
    size_t EntryCount() const { return store_.dwWriteDescriptorCount; }

    int ReadGPT();
};

// ---------------- Open / Close ----------------
int FFUImage::Open(const char *path) {
    Close();
#ifdef _WIN32
    fd_ = open(path, O_RDONLY | _O_BINARY);
#else
    fd_ = open(path, O_RDONLY);
#endif
    if (fd_ < 0) { perror("open ffu"); return -1; }
    return 0;
}

void FFUImage::Close() {
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    validation_.clear();
    block_entries_raw_.clear();
    gpt_entries_.clear();
}

// ---------------- Parse ----------------
int FFUImage::Parse() {
    if (fd_ < 0) return -1;

    if (Pread(&sec_, sizeof(sec_), 0) != (ssize_t)sizeof(sec_)) {
        fprintf(stderr, "read security header failed\n"); return -1;
    }
    if (memcmp(sec_.signature, "SignedImage ", 12) != 0) {
        fprintf(stderr, "bad security signature\n"); return -1;
    }

    uint64_t chunk = (uint64_t)sec_.dwChunkSizeInKb * 1024;
    if (chunk == 0) { fprintf(stderr, "chunk size is 0\n"); return -1; }

    // IMAGE_HEADER
    uint64_t cur_end = sizeof(SECURITY_HEADER) + sec_.dwCatalogSize + sec_.dwHashTableSize;
    uint64_t next = GetNextStartingArea(chunk, cur_end);
    if (Pread(&img_, sizeof(img_), next) != (ssize_t)sizeof(img_)) {
        fprintf(stderr, "read image header failed\n"); return -1;
    }

    // STORE_HEADER
    cur_end = next + sizeof(IMAGE_HEADER) + img_.ManifestLength;
    next = GetNextStartingArea(chunk, cur_end);
    if (Pread(&store_, sizeof(store_), next) != (ssize_t)sizeof(store_)) {
        fprintf(stderr, "read store header failed\n"); return -1;
    }

    // ValidationEntries
    next += sizeof(STORE_HEADER);
    next = GetNextStartingArea(sizeof(BLOCK_DATA_ENTRY), next);
    if (store_.dwValidateDescriptorLength > 0) {
        validation_.resize(store_.dwValidateDescriptorLength);
        if (Pread(validation_.data(), validation_.size(), next) != (ssize_t)validation_.size()) {
            fprintf(stderr, "read validation entries failed\n"); return -1;
        }
        next += store_.dwValidateDescriptorLength;
    }

    // BlockDataEntries
    if (store_.dwWriteDescriptorLength > 0) {
        block_entries_raw_.resize(store_.dwWriteDescriptorLength);
        if (Pread(block_entries_raw_.data(), block_entries_raw_.size(), next)
            != (ssize_t)block_entries_raw_.size()) {
            fprintf(stderr, "read block data entries failed\n"); return -1;
        }
        next += store_.dwWriteDescriptorLength;
    }

    // PayloadDataStart
    payload_start_ = GetNextStartingArea(chunk, next);

    fprintf(stderr,
            "[parse] blockSize=%u, writeCount=%u, payloadStart=%llu\n"
            "[parse] chunk=%llu, catalog=%u, hashTable=%u, manifest=%u\n"
            "[parse] GPT idx: initial=%u flashOnly=%u final=%u (count=%u)\n",
            store_.dwBlockSizeInBytes, store_.dwWriteDescriptorCount,
            (unsigned long long)payload_start_,
            (unsigned long long)chunk,
            sec_.dwCatalogSize, sec_.dwHashTableSize, img_.ManifestLength,
            store_.dwInitialTableIndex, store_.dwFlashOnlyTableIndex,
            store_.dwFinalTableIndex, store_.dwFinalTableCount);

    return ReadGPT();
}

// ---------------- ReadGPT ----------------
int FFUImage::ReadGPT() {
    if (store_.dwBlockSizeInBytes == 0) { fprintf(stderr, "block size 0\n"); return -1; }
    uint64_t B = store_.dwBlockSizeInBytes;
    uint64_t gpt_off = payload_start_ + (uint64_t)store_.dwFinalTableIndex * B;

    fprintf(stderr, "[gpt] finalTableIndex=%u, gpt_off=%llu\n",
            store_.dwFinalTableIndex, (unsigned long long)gpt_off);

    unsigned char mbr[512];
    if (Pread(mbr, 512, gpt_off) != 512) {
        fprintf(stderr, "read protective MBR failed\n"); return -1;
    }

    if (Pread(&gpt_hdr_, sizeof(gpt_hdr_), gpt_off + 512) != (ssize_t)sizeof(gpt_hdr_)) {
        fprintf(stderr, "read gpt header failed\n"); return -1;
    }

    fprintf(stderr, "[gpt] sig=%.8s header_size=%u entry_lba=%llu num=%u esize=%u\n",
            gpt_hdr_.signature,
            gpt_hdr_.header_size,
            (unsigned long long)gpt_hdr_.partition_entry_lba,
            gpt_hdr_.num_partition_entries,
            gpt_hdr_.sizeof_partition_entry);

    if (memcmp(gpt_hdr_.signature, "EFI PART", 8) != 0) {
        fprintf(stderr, "bad GPT signature\n");
        return -1;
    }

    // 用 partition_entry_lba 定位 entries（相对 gpt_off 的 512 扇区）
    uint64_t entries_off = gpt_off + (uint64_t)gpt_hdr_.partition_entry_lba * 512;
    uint32_t n_entries = gpt_hdr_.num_partition_entries ? gpt_hdr_.num_partition_entries : 128;
    uint32_t e_size    = gpt_hdr_.sizeof_partition_entry ? gpt_hdr_.sizeof_partition_entry : sizeof(gpt_entry_t);

    if (n_entries > 128) n_entries = 128;
    if (e_size != sizeof(gpt_entry_t)) {
        fprintf(stderr, "[gpt] warn: header entry_size=%u, struct=%zu\n",
                e_size, sizeof(gpt_entry_t));
    }

    gpt_entries_.resize(n_entries);
    size_t total = (size_t)n_entries * sizeof(gpt_entry_t);
    if (Pread(gpt_entries_.data(), total, entries_off) != (ssize_t)total) {
        fprintf(stderr, "read gpt entries failed\n");
        return -1;
    }

    int valid = 0;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (gpt_entries_[i].partition_type_guid[0] == 0) continue;
        std::string name = utf16le_to_ascii(gpt_entries_[i].part_name,
                                            sizeof(gpt_entries_[i].part_name));
        if (name.empty()) continue;
        valid++;
        fprintf(stderr, "[gpt] %-24s first=%-10llu last=%-10llu\n",
                name.c_str(),
                (unsigned long long)gpt_entries_[i].first_lba,
                (unsigned long long)gpt_entries_[i].last_lba);
    }
    fprintf(stderr, "[gpt] %d valid partitions\n", valid);
    return valid > 0 ? 0 : -1;
}

// ---------------- EntryAt ----------------
const uint8_t *FFUImage::EntryAt(size_t index, uint32_t *loc_count_out) const {
    if (index >= store_.dwWriteDescriptorCount) return nullptr;
    const uint8_t *p = block_entries_raw_.data();
    const uint8_t *end = p + block_entries_raw_.size();
    for (size_t i = 0; i < index; i++) {
        if (p + 8 > end) return nullptr;
        uint32_t lc;
        memcpy(&lc, p, 4);
        size_t esz = 8 + (size_t)lc * sizeof(DISK_LOCATION);
        if (p + esz > end) return nullptr;
        p += esz;
    }
    if (p + 8 > end) return nullptr;
    memcpy(loc_count_out, p, 4);
    return p;
}

// ---------------- DumpRawProgram ----------------
int FFUImage::DumpRawProgram(const char *out_xml) {
    FILE *fp = fopen(out_xml, "w");
    if (!fp) { perror("fopen xml"); return -1; }

    fprintf(fp, "<?xml version=\"1.0\" ?>\n<data>\n");

    uint64_t B = store_.dwBlockSizeInBytes;
    uint32_t spb = (uint32_t)(B / 512);

    uint64_t dwBlockOffset = 0;
    bool     pending = false;
    uint64_t disk_offset = 0;
    uint64_t start_block = 0;
    uint64_t next_block_index = 0;

    auto flush = [&](uint64_t num_blocks, uint64_t disk_byte_off) {
        if (!pending || num_blocks == 0) return;
        uint64_t file_off_sectors = (payload_start_ + start_block * B) / 512;
        int64_t  start_sector     = (int64_t)(disk_byte_off / 512);
        uint64_t num_sectors      = num_blocks * spb;
        fprintf(fp,
                "<program SECTOR_SIZE_IN_BYTES=\"512\" file_sector_offset=\"%llu\" "
                "filename=\"FFU\" label=\"ffu_image_%lld\" num_partition_sectors=\"%llu\" "
                "physical_partition_number=\"0\" size_in_KB=\"%llu\" sparse=\"false\" "
                "start_byte_hex=\"0x%llx\" start_sector=\"%lld\"/>\n",
                (unsigned long long)file_off_sectors,
                (long long)start_sector,
                (unsigned long long)num_sectors,
                (unsigned long long)(num_sectors / 2),
                (unsigned long long)(start_sector * 512),
                (long long)start_sector);
    };

    for (size_t i = 0; i < EntryCount(); i++) {
        uint32_t lc = 0;
        const uint8_t *e = EntryAt(i, &lc);
        if (!e) { fprintf(stderr, "EntryAt(%zu) failed\n", i); break; }
        const DISK_LOCATION *locs = (const DISK_LOCATION *)(e + 8);

        for (uint32_t j = 0; j < lc; j++) {
            uint32_t method = locs[j].dwDiskAccessMethod;
            uint32_t bidx   = locs[j].dwBlockIndex;

            if (method == DISK_BEGIN) {
                if (bidx != next_block_index) {
                    flush(dwBlockOffset - start_block, disk_offset);
                    disk_offset = (uint64_t)bidx * B;
                    start_block = dwBlockOffset;
                    pending = true;
                } else if (!pending) {
                    disk_offset = (uint64_t)bidx * B;
                    start_block = dwBlockOffset;
                    pending = true;
                }
                next_block_index = (uint64_t)bidx + 1;
            } else if (method == DISK_END) {
                flush(dwBlockOffset - start_block, disk_offset);

                uint64_t file_off_sectors = (payload_start_ + dwBlockOffset * B) / 512;
                uint64_t num_sectors      = B / 512;
                fprintf(fp,
                        "<program SECTOR_SIZE_IN_BYTES=\"512\" file_sector_offset=\"%llu\" "
                        "filename=\"FFU\" label=\"ffu_image_-%llu\" num_partition_sectors=\"%llu\" "
                        "physical_partition_number=\"0\" size_in_KB=\"%llu\" sparse=\"false\" "
                        "start_byte_hex=\"0xfffffffffffe0000\" "
                        "start_sector=\"NUM_DISK_SECTORS-%llu\"/>\n",
                        (unsigned long long)file_off_sectors,
                        (unsigned long long)num_sectors,
                        (unsigned long long)num_sectors,
                        (unsigned long long)(num_sectors / 2),
                        (unsigned long long)num_sectors);
                pending = false;
            }
        }
        dwBlockOffset++;
    }
    flush(dwBlockOffset - start_block, disk_offset);

    fprintf(fp, "</data>\n");
    fclose(fp);
    return 0;
}

// ---------------- SplitAll ----------------
int FFUImage::SplitAll(const char *out_dir) {
    uint64_t B = store_.dwBlockSizeInBytes;
    if (B == 0) return -1;
    uint32_t spb = (uint32_t)(B / 512);

    struct Part { std::string name; uint64_t first, last; int fd; };
    std::vector<Part> parts;

    for (int i = 0; i < (int)gpt_entries_.size(); i++) {
        if (gpt_entries_[i].partition_type_guid[0] == 0) continue;
        std::string name = utf16le_to_ascii(gpt_entries_[i].part_name,
                                            sizeof(gpt_entries_[i].part_name));
        if (name.empty()) continue;
        if (name == "CrashDump") continue;

        // sanitize：防路径穿越
        for (auto &c : name) if (c == '/' || c == '\\' || c == ':') c = '_';

        uint64_t first = gpt_entries_[i].first_lba;
        uint64_t last  = gpt_entries_[i].last_lba;

        if (last < first) {
            fprintf(stderr, "[split] skip %-24s: last(%llu) < first(%llu)\n",
                    name.c_str(),
                    (unsigned long long)last,
                    (unsigned long long)first);
            continue;
        }

        uint64_t nsectors = last - first + 1;
        if (nsectors > (uint64_t)0x7FFFFFFFFFFFFFFFULL / 512ULL) {
            fprintf(stderr, "[split] skip %-24s: size overflow (%llu sectors)\n",
                    name.c_str(), (unsigned long long)nsectors);
            continue;
        }
        uint64_t size = nsectors * 512ULL;

        std::string path = std::string(out_dir) + "/" + name + ".bin";
#ifdef _WIN32
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | _O_BINARY, 0644);
#else
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
#endif
        if (fd < 0) {
            fprintf(stderr, "[split] open %s failed: errno=%d (%s)\n",
                    path.c_str(), errno, strerror(errno));
            continue;
        }

        if (ffu_truncate(fd, size) != 0) {
            fprintf(stderr, "[split] truncate %-24s failed: size=%llu errno=%d (%s)\n",
                    name.c_str(), (unsigned long long)size, errno, strerror(errno));
            ::close(fd);
            continue;
        }

        fprintf(stderr, "[split] %-24s first=%-10llu size=%llu bytes\n",
                name.c_str(), (unsigned long long)first, (unsigned long long)size);

        parts.push_back({name, first, last, fd});
    }

    if (parts.empty()) {
        fprintf(stderr, "[split] no partitions to write\n");
        return -1;
    }

    std::vector<uint8_t> blk(B);
    for (size_t i = 0; i < EntryCount(); i++) {
        uint32_t lc = 0;
        const uint8_t *e = EntryAt(i, &lc);
        if (!e) { fprintf(stderr, "EntryAt(%zu) failed\n", i); break; }

        uint64_t payload_off = payload_start_ + (uint64_t)i * B;
        if (Pread(blk.data(), B, payload_off) != (ssize_t)B) {
            fprintf(stderr, "read payload block %zu failed (off=%llu)\n",
                    i, (unsigned long long)payload_off);
            break;
        }

        const DISK_LOCATION *locs = (const DISK_LOCATION *)(e + 8);
        for (uint32_t j = 0; j < lc; j++) {
            if (locs[j].dwDiskAccessMethod == DISK_END) continue;
            uint64_t bf = (uint64_t)locs[j].dwBlockIndex * spb;
            uint64_t bl = bf + spb - 1;

            for (auto &p : parts) {
                uint64_t lo = std::max(bf, p.first);
                uint64_t hi = std::min(bl, p.last);
                if (lo > hi) continue;

                uint64_t src_off = (lo - bf) * 512;
                uint64_t dst_off = (lo - p.first) * 512;
                uint64_t len     = (hi - lo + 1) * 512;
                if (pwrite64(p.fd, blk.data() + src_off, (size_t)len, (int64_t)dst_off)
                    != (ssize_t)len) {
                    fprintf(stderr, "[split] pwrite %s failed: dst=%llu len=%llu errno=%d\n",
                            p.name.c_str(),
                            (unsigned long long)dst_off,
                            (unsigned long long)len,
                            errno);
                }
            }
        }
    }

    for (auto &p : parts) ::close(p.fd);
    fprintf(stderr, "[split] done, %zu partitions written\n", parts.size());
    return 0;
}

// ===================== main =====================
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <ffu> rawprogram <out.xml>\n"
            "  %s <ffu> split      <out_dir>\n", argv[0], argv[0]);
        return 1;
    }

    FFUImage ffu;
    if (ffu.Open(argv[1]) != 0) return 1;
    if (ffu.Parse() != 0) { fprintf(stderr, "parse failed\n"); return 1; }

    if (strcmp(argv[2], "rawprogram") == 0)
        return ffu.DumpRawProgram(argv[3]);
    else if (strcmp(argv[2], "split") == 0)
        return ffu.SplitAll(argv[3]);

    fprintf(stderr, "unknown mode: %s\n", argv[2]);
    return 1;
}
