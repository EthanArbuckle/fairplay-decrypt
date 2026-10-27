/* On-device FairPlay credential retriever. No Python runtime. */
#include "finalizer.h"
#include "selector_native.h"
#include "core4_native.h"
#include "observer.h"
#include <CommonCrypto/CommonCryptor.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

enum { FILE_LIMIT = 32 * 1024 * 1024, TABLE_SIZE = 4096 };
static const uint8_t DESCRIPTOR_A[16] = {0xed, 0x9c, 0x70, 0x1f, 0x5f, 0x35, 0x81, 0x7a, 0x1f, 0xb9, 0x49, 0x2d, 0xaf, 0xbb, 0x96, 0x82};
static const uint8_t DESCRIPTOR_B[16] = {0xed, 0x5f, 0x59, 0xff, 0x4f, 0xa2, 0xc3, 0x04, 0xc7, 0xd4, 0x59, 0x77, 0xf4, 0x92, 0x51, 0x0d};
static const uint8_t DESCRIPTOR_C[16] = {0xda, 0x52, 0xf1, 0x36, 0xdf, 0x88, 0xfa, 0xb8, 0xb7, 0x1a, 0x5a, 0xec, 0xcd, 0xf3, 0xdd, 0x56};
static const uint8_t DESCRIPTOR_PREFIX[48] = {0xb1, 0x4c, 0x14, 0x2e, 0x3b, 0x93, 0x0c, 0x36, 0xf1, 0x52, 0x6a, 0x60, 0x0f, 0x52, 0xc6, 0xca, 0x7b, 0xf8, 0xe8, 0x9d, 0x94, 0x5c, 0x9b, 0xe0, 0x09, 0x5f, 0x83, 0x42, 0xd8, 0xea, 0xaf, 0x65, 0xb7, 0xb0, 0x2e, 0xbc, 0xdc, 0xf1, 0xff, 0x46, 0x0f, 0x47, 0x8e, 0x2f, 0x6f, 0x31, 0x56, 0x63};
static const uint8_t DESCRIPTOR_TAIL[16] = {0xf7, 0xe5, 0x41, 0x3e, 0xfc, 0x76, 0xc6, 0x52, 0xe4, 0xfa, 0xd8, 0x0e, 0x1f, 0x20, 0x28, 0x55};
static const uint8_t KEYBAG_IV[16] = {0x2c, 0x67, 0xd5, 0xc1, 0x0c, 0xf4, 0x27, 0x3d, 0xd4, 0x06, 0xce, 0x0f, 0x8f, 0xd0, 0x42, 0xa6};
static const uint8_t SELECTOR_IV_OBFUSCATED[16] = {0xbf, 0x8c, 0x63, 0x26, 0x06, 0xed, 0xd0, 0xb0, 0x02, 0xd6, 0x10, 0x0e, 0x0a, 0x0a, 0x7d, 0xfc};

typedef struct {
    uint8_t *data;
    size_t size;
} Bytes;

static int read_file(const char *path, Bytes *out) {
    struct stat info;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (fstat(fd, &info) || info.st_size < 0 || info.st_size > FILE_LIMIT) {
        close(fd);
        return -1;
    }

    size_t size = (size_t)info.st_size;
    uint8_t *data = malloc(size ? size : 1);
    if (!data) {
        close(fd);
        return -1;
    }

    size_t at = 0;
    while (at < size) {
        ssize_t got = read(fd, data + at, size - at);
        if (got <= 0) {
            free(data);
            close(fd);
            return -1;
        }

        at += (size_t)got;
    }

    if (close(fd)) {
        free(data);
        return -1;
    }

    *out = (Bytes){data, size};
    return 0;
}

static int write_new(const char *path, const uint8_t *data, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -1;
    }

    size_t at = 0;
    while (at < size) {
        ssize_t wrote = write(fd, data + at, size - at);
        if (wrote <= 0) {
            close(fd);
            return -1;
        }

        at += (size_t)wrote;
    }

    int status = fsync(fd) | close(fd);
    return status ? -1 : 0;
}

static uint32_t be32(const uint8_t *data) { return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3]; }

static int atom_field(const Bytes sinf, const char tag[4], Bytes *field) {
    if (sinf.size < 16 || be32(sinf.data) != sinf.size || memcmp(sinf.data + 4, "sinf", 4)) {
        return -1;
    }

    size_t at = 8;
    size_t schi_start = 0, schi_end = 0;
    while (at < sinf.size) {
        if (at + 8 > sinf.size) {
            return -1;
        }

        uint32_t size = be32(sinf.data + at);
        if (size < 8 || size > sinf.size - at) {
            return -1;
        }

        if (!memcmp(sinf.data + at + 4, "schi", 4)) {
            if (schi_end) {
                return -1;
            }

            schi_start = at + 8;
            schi_end = at + size;
        }

        at += size;
    }

    if (!schi_end) {
        return -1;
    }

    at = schi_start;
    int matches = 0;
    while (at < schi_end) {
        if (at + 8 > schi_end) {
            return -1;
        }

        uint32_t size = be32(sinf.data + at);
        if (size < 8 || size > schi_end - at) {
            return -1;
        }

        if (!memcmp(sinf.data + at + 4, tag, 4)) {
            *field = (Bytes){sinf.data + at + 8, size - 8};
            matches++;
        }

        at += size;
    }

    return matches == 1 ? 0 : -1;
}

static void tail(const uint8_t source[16], const uint8_t table[TABLE_SIZE], uint8_t credential[16]) {
    for (size_t i = 0; i < 16; i++) {
        uint8_t first = (uint8_t)(((source[i] ^ 0x30) * -13) - 111);
        uint8_t index = (uint8_t)(first * 59 - 107);
        uint8_t second = (uint8_t)(table[i * 256 + index] * -13 - 111);
        credential[i] = (uint8_t)(second * 59 - ((second * 118 + 42) & 96) - 59);
    }
}

static int descriptor_pre(const uint8_t udid[20], uint8_t state[64]) {
    const uint8_t *a = DESCRIPTOR_A, *b = DESCRIPTOR_B, *c = DESCRIPTOR_C;

    memcpy(state, DESCRIPTOR_PREFIX, 48);
    memcpy(state + 48, DESCRIPTOR_TAIL, 16);
    const uint32_t constant = 491398319;
    for (uint32_t step = 0; step < 20; step++) {
        uint32_t lane = step & 15;
        uint32_t t0 = udid[step];
        uint32_t source = state[(step + 1) % 48] ^ 46;
        uint32_t t1 = udid[(udid[source % 20] + step) % 20];
        uint32_t mix = a[lane] ^ (lane * 121) ^ b[lane] ^ c[lane];
        uint32_t raw = mix ^ t0 ^ t1 ^ state[48 + lane];
        state[48 + lane] = (uint8_t)(mix ^ raw);
        uint32_t control_word = (raw & 255) + constant;
        control_word -= 350 & ((raw & 255) << 1);
        uint32_t control = control_word ^ constant;
        uint32_t prior = state[control % 48];
        uint32_t prior_first = state[step % 48];
        uint32_t x, new_tail, new_first;
        if ((raw & 255) <= (prior ^ 46)) {
            uint32_t v1 = state[((constant + 59) ^ control_word) % 48];
            uint32_t v2 = udid[((constant - 131) ^ control_word) % 20];
            v2 = v2 - (92 & (v2 << 1)) + 46;
            uint32_t index = (((constant - 121) ^ control_word) + step) % 20;
            uint32_t v3 = udid[index];
            v3 = state[v3 % 48] ^ 46;
            v3 = state[v3 % 48] ^ 46;
            v3 = udid[v3 % 20];
            x = raw ^ 40 ^ v1 ^ v2 ^ v3 ^ 75;
            new_tail = (mix ^ x ^ 99) & 255;
            new_first = ((x & 171) ^ prior_first ^ 35) & 255;
        } else {
            uint32_t v1 = udid[control % 20];
            v1 = v1 - (92 & (v1 << 1)) + 46;
            uint32_t v2 = udid[(control + step) % 20];
            v2 = state[v2 % 48] ^ 46;
            v2 = state[v2 % 48] ^ 46;
            v2 = udid[v2 % 20];
            x = prior ^ (raw ^ 40) ^ v1 ^ v2 ^ 87;
            new_tail = (mix ^ x ^ 127) & 255;
            uint32_t swap = ((x << 4) | ((x >> 4) & 15)) & 255;
            new_first = (prior_first ^ swap ^ 247) & 255;
        }

        state[48 + lane] = (uint8_t)new_tail;
        state[step % 48] = (uint8_t)new_first;
    }

    return 0;
}

static int descriptor_rec(const uint8_t initial[64], uint8_t output[64]) {
    const uint8_t *a = DESCRIPTOR_A, *b = DESCRIPTOR_B, *c = DESCRIPTOR_C;

    uint8_t state[64];
    memcpy(state, initial, 64);
    for (uint32_t step = 0; step < 64; step++) {
        uint32_t lane = step & 15;
        uint32_t mixed = state[48 + lane] ^ a[lane] ^ b[lane] ^ c[lane] ^ ((lane * 121) & 255);
        uint32_t control = (mixed ^ UINT32_C(1068482492)) + (376 & (mixed << 1));
        uint32_t select = (control + 4) & 15;
        uint32_t source_index = (control + UINT32_C(3226484804)) % 48;
        output[step] = (uint8_t)(state[48 + select] ^ state[source_index] ^ a[select] ^ b[select] ^ c[select] ^ ((select * 121) & 255) ^ 30);
        uint32_t first_index = step % 48;
        uint32_t old = state[first_index];
        select = (old & 15) ^ 14;
        uint32_t new_first = state[48 + select] ^ old ^ ((mixed & 240) >> 4) ^ a[select] ^ b[select] ^ c[select] ^ ((select * 121) & 255);
        state[first_index] = (uint8_t)new_first;
        select = (new_first & 15) ^ 14;
        uint32_t candidate = state[48 + select] ^ a[select] ^ b[select] ^ c[select] ^ ((select * 121) & 255);
        state[48 + lane] = (uint8_t)(state[candidate % 48] ^ state[48 + lane] ^ 46);
    }

    return 0;
}

static int descriptor_finish(const uint8_t initial[64], uint8_t output[64]) {
    memcpy(output, initial, 64);
    return finalizer_transform(output + 48);
}

static int hex_byte(char first, char second, uint8_t *value) {
    int pair[2];
    char chars[2] = {first, second};
    for (size_t i = 0; i < 2; i++) {
        if (chars[i] >= '0' && chars[i] <= '9') {
            pair[i] = chars[i] - '0';
        } else if (chars[i] >= 'a' && chars[i] <= 'f') {
            pair[i] = chars[i] - 'a' + 10;
        } else if (chars[i] >= 'A' && chars[i] <= 'F') {
            pair[i] = chars[i] - 'A' + 10;
        } else {
            return -1;
        }
    }

    *value = (uint8_t)((pair[0] << 4) | pair[1]);
    return 0;
}

static int parse_udid(const char *hex, uint8_t udid[20]) {
    /* iOS 16.3.1 fairplayd.H2: new-format UDID becomes a fixed 8-byte
     * prefix followed by the 12 decoded bytes, preserving textual order.
     * Verified at 0x1002789d4 and the parser's runtime output. */
    if (strlen(hex) == 25 && hex[8] == '-') {
        static const uint8_t prefix[8] = {0x60, 0x97, 0xa4, 0xb0, 0xc2, 0x0a, 0x0a, 0x9f};
        memcpy(udid, prefix, sizeof(prefix));
        for (size_t i = 0; i < 12; i++) {
            size_t at = i * 2 + (i >= 4);
            if (hex_byte(hex[at], hex[at + 1], &udid[8 + i])) {
                return -1;
            }
        }
        return 0;
    }
    if (strlen(hex) != 40) {
        return -1;
    }

    for (size_t i = 0; i < 20; i++) {
        if (hex_byte(hex[i * 2], hex[i * 2 + 1], &udid[i])) {
            return -1;
        }
    }

    return 0;
}

static int device_udid(uint8_t udid[20]) {
    void *library = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (!library) {
        return -1;
    }

    CFTypeRef (*copy_answer)(CFStringRef) = dlsym(library, "MGCopyAnswer");
    if (!copy_answer) {
        dlclose(library);
        return -1;
    }

    CFStringRef name = CFStringCreateWithCString(NULL, "UniqueDeviceID", kCFStringEncodingUTF8);
    if (!name) {
        dlclose(library);
        return -1;
    }

    CFTypeRef answer = copy_answer(name);
    CFRelease(name);
    char hex[64] = {0};
    int status = -1;
    if (answer && CFGetTypeID(answer) == CFStringGetTypeID() && CFStringGetCString((CFStringRef)answer, hex, sizeof(hex), kCFStringEncodingUTF8)) {
        status = parse_udid(hex, udid);
    }

    if (answer) {
        CFRelease(answer);
    }

    dlclose(library);
    return status;
}

static int descriptor_key(const uint8_t udid[20], uint8_t key[16]) {
    uint8_t before[64], after[64], rec[64];
    if (descriptor_pre(udid, before) || descriptor_finish(before, after) || descriptor_rec(after, rec)) {
        return -1;
    }

    for (size_t i = 0; i < 16; i++) {
        key[i] = rec[21 + i] ^ 0x30;
    }

    memset(before, 0, sizeof(before));
    memset(after, 0, sizeof(after));
    memset(rec, 0, sizeof(rec));
    return 0;
}

static int keybag_clear_from_uid_layer(const Bytes uid, const uint8_t udid[20], Bytes *clear) {
    if (!uid.data || !uid.size || uid.size % 16) {
        return -1;
    }

    uint8_t key[16];
    if (descriptor_key(udid, key)) {
        return -1;
    }

    uint8_t *output = malloc(uid.size);
    if (!output) {
        return -1;
    }

    size_t written = 0;
    CCCryptorStatus result = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key, 16, KEYBAG_IV, uid.data, uid.size, output, uid.size, &written);
    memset(key, 0, sizeof(key));
    if (result != kCCSuccess || written != uid.size) {
        free(output);
        return -1;
    }

    *clear = (Bytes){output, written};
    return 0;
}

typedef struct {
    const uint8_t *session;
    const uint8_t *scra;
    const uint8_t *value;
    unsigned users, keys, sessions, scras, values;
} Selection;

static int atom_container(const uint8_t tag[4]) {
    static const char *tags[] = {"sean", "grup", "head", "user", "key ", "tail"};
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++) {
        if (!memcmp(tag, tags[i], 4)) {
            return 1;
        }
    }

    return 0;
}

static int scan_atoms(const Bytes clear, size_t start, size_t end, const uint8_t account[4], const uint8_t index[4], Selection *found, int selected_user, int selected_key, unsigned depth) {
    if (depth > 16 || start > end || end > clear.size) {
        return -1;
    }

    size_t at = start;
    while (at < end) {
        if (at + 20 > end) {
            return -1;
        }

        const uint8_t *node = clear.data + at;
        uint32_t size = be32(node);
        if (size < 20 || size > end - at) {
            return -1;
        }

        for (size_t i = 4; i < 8; i++) {
            if (node[i] < 32 || node[i] >= 127) {
                return -1;
            }
        }

        int user = selected_user, key = selected_key;
        const uint8_t *payload = node + 20;
        size_t payload_size = size - 20;
        if (!memcmp(node + 4, "user", 4)) {
            user = !memcmp(node + 8, account, 4);
            key = 0;
            if (user) {
                found->users++;
            }
        } else if (!memcmp(node + 4, "key ", 4)) {
            key = user && !memcmp(node + 8, index, 4);
            if (key) {
                found->keys++;
            }
        } else if (user && !memcmp(node + 4, "sess", 4)) {
            if (payload_size != 256) {
                return -1;
            }

            found->session = payload;
            found->sessions++;
        } else if (user && !memcmp(node + 4, "scra", 4)) {
            if (payload_size != 49) {
                return -1;
            }

            found->scra = payload;
            found->scras++;
        } else if (key && !memcmp(node + 4, "valu", 4)) {
            if (payload_size != 16) {
                return -1;
            }

            found->value = payload;
            found->values++;
        }

        if (atom_container(node + 4) && scan_atoms(clear, at + 20, at + size, account, index, found, user, key, depth + 1)) {
            return -1;
        }

        at += size;
    }

    return 0;
}

static int select_license(const Bytes clear, const Bytes sinf, Selection *selected) {
    Bytes account = {0}, index = {0};
    if (atom_field(sinf, "user", &account) || atom_field(sinf, "key ", &index) || account.size != 4 || index.size != 4 || clear.size < 32 || memcmp(clear.data, "\0\0\0\0\0\0\0\0\0\0\0\0", 12)) {
        return -1;
    }

    uint32_t size = be32(clear.data + 12);
    if (size < 20 || size > clear.size - 12) {
        return -1;
    }

    memset(selected, 0, sizeof(*selected));
    if (scan_atoms(clear, 12, 12 + size, account.data, index.data, selected, 0, 0, 0)) {
        return -1;
    }

    return selected->users == 1 && selected->keys == 1 && selected->sessions == 1 && selected->scras == 1 && selected->values == 1 ? 0 : -1;
}

static int core3(const Selection *selected, const uint8_t sidewrite[16], uint8_t output[16]) {
    size_t written = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, sidewrite, 16, NULL, selected->value, 16, output, 16, &written);
    if (status != kCCSuccess || written != 16) {
        return -1;
    }

    for (size_t i = 0; i < 16; i++) {
        output[i] ^= 0x30;
    }

    return 0;
}

static void append_bytes(uint8_t *destination, size_t *offset, const uint8_t *source, size_t length) {
    memcpy(destination + *offset, source, length);
    *offset += length;
}

static int selector_body(const Selection *selected, uint64_t body_address, uint8_t output[160]) {
    static const uint8_t control_a[16] = {
        0x00, 0xfb, 0x19, 0x58, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0xfb, 0x19, 0x58,
    };
    static const uint8_t control_b[16] = {
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0xc0, 0x88, 0x00, 0x00, 0x00, 0x31,
    };
    static const uint8_t post_scra[8] = {0x00, 0x5f, 0xc0, 0x88, 0, 0, 0, 0x10};
    static const uint8_t after_iv[7] = {0x00, 0xfb, 0x19, 0x58, 0, 0, 0};
    static const uint8_t prefix[4] = {8, 0, 0, 0};
    static const uint8_t ending[16] = {
        4, 0, 0, 0, 0x10, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t expected_mask[16] = {
        0x01, 0xfc, 0x9c, 0xbf, 0xc0, 0x02, 0xdf, 0x61, 0xa1, 0x64, 0x4e, 0xf2, 0x57, 0x92, 0xd8, 0xeb,
    };
    if (body_address < 384 || body_address >= (UINT64_C(1) << 40)) {
        return -1;
    }

    uint8_t plain[160];
    size_t at = 0;
    append_bytes(plain, &at, control_a, 16);
    append_bytes(plain, &at, control_b, 16);
    append_bytes(plain, &at, selected->scra, 49);
    append_bytes(plain, &at, post_scra, 8);
    for (size_t i = 0; i < 16; i++) {
        plain[at++] = SELECTOR_IV_OBFUSCATED[i] ^ 0x30;
    }

    for (size_t part = 0; part < 2; part++) {
        append_bytes(plain, &at, after_iv, 7);
        append_bytes(plain, &at, prefix, 4);
        uint64_t pointer = body_address - (part ? 384 : 319);
        for (int byte = 4; byte >= 0; byte--) {
            plain[at++] = (uint8_t)(pointer >> (byte * 8));
        }
    }

    append_bytes(plain, &at, after_iv, 7);
    append_bytes(plain, &at, ending, 16);
    if (at != sizeof(plain)) {
        return -1;
    }

    for (size_t i = 0; i < sizeof(plain); i++) {
        output[i] = plain[i] ^ expected_mask[i & 15];
    }

    return 0;
}

static int selector_request(const Selection *selected, uint64_t body_address, uint8_t output[552]) {
    uint8_t body[160];
    if (selector_body(selected, body_address, body)) {
        return -1;
    }

    return selector_request_native(body, output);
}

static int core4_context(const Bytes sinf, const uint8_t udid[20], const uint8_t table[CORE4_WORD_TABLE_SIZE], uint8_t output[16]) {
    Bytes account = {0}, index_raw = {0};
    if (atom_field(sinf, "user", &account) || atom_field(sinf, "key ", &index_raw) || account.size != 4 || index_raw.size != 4) {
        return -1;
    }

    uint8_t message[16];
    memcpy(message, udid, 8);
    memcpy(message + 8, index_raw.data, 4);
    memcpy(message + 12, account.data, 4);

    return core4_context_native(message, table, output);
}

static int finish_credential(const uint8_t core3_block[16], const uint8_t context[16], const uint8_t table[TABLE_SIZE], uint8_t credential[16]) {
    uint8_t key[16], input[16], source[16];
    for (size_t i = 0; i < 16; i++) {
        key[i] = context[i] ^ 0x30;
        input[i] = core3_block[i] ^ 0x30;
    }

    size_t written = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, key, 16, NULL, input, 16, source, 16, &written);
    memset(key, 0, sizeof(key));
    if (status != kCCSuccess || written != 16) {
        return -1;
    }

    for (size_t i = 0; i < 16; i++) {
        source[i] ^= 0x30;
    }

    tail(source, table, credential);
    memset(source, 0, sizeof(source));
    return 0;
}

static int run_device_udid(int argc, char **argv) {
    if (argc != 3) {
        return 2;
    }

    uint8_t udid[20];
    return device_udid(udid) || write_new(argv[2], udid, sizeof(udid)) ? 1 : 0;
}

static int companion_path(const char *name, char output[PATH_MAX]) {
    char executable[PATH_MAX], resolved[PATH_MAX];
    uint32_t length = sizeof(executable);
    if (_NSGetExecutablePath(executable, &length) || !realpath(executable, resolved)) {
        return -1;
    }

    char *slash = strrchr(resolved, '/');
    if (!slash) {
        return -1;
    }

    slash[1] = '\0';
    int written = snprintf(output, PATH_MAX, "%s%s", resolved, name);
    return written > 0 && written < PATH_MAX ? 0 : -1;
}

static int run_child(const char *program, char *const arguments[]) {
    extern char **environ;
    pid_t child = 0;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions)) {
        return -1;
    }

    if (posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)) {
        posix_spawn_file_actions_destroy(&actions);
        return -1;
    }

    int started = posix_spawn(&child, program, &actions, NULL, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (started) {
        fprintf(stderr, "cannot start %s: %s\n", program, strerror(started));
        return -1;
    }

    int state = 0;
    if (waitpid(child, &state, 0) != child || !WIFEXITED(state)) {
        return -1;
    }

    return WEXITSTATUS(state);
}

static int capture_child(const char *program, char *const arguments[], size_t limit, Bytes *output) {
    extern char **environ;
    int ends[2];
    if (pipe(ends)) {
        return -1;
    }

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions)) {
        close(ends[0]);
        close(ends[1]);
        return -1;
    }

    int configured = posix_spawn_file_actions_adddup2(&actions, ends[1], STDOUT_FILENO) || posix_spawn_file_actions_addclose(&actions, ends[0]) || posix_spawn_file_actions_addclose(&actions, ends[1]);
    pid_t child = 0;
    int started = configured ? -1 : posix_spawn(&child, program, &actions, NULL, arguments, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(ends[1]);
    if (started) {
        close(ends[0]);
        return -1;
    }

    uint8_t *data = malloc(limit + 1);
    size_t size = 0;
    int failed = data == NULL;
    if (!failed) {
        while (size <= limit) {
            ssize_t got = read(ends[0], data + size, limit + 1 - size);
            if (got < 0 && errno == EINTR) {
                continue;
            }

            if (got < 0) {
                failed = 1;
            }

            if (got <= 0) {
                break;
            }

            size += (size_t)got;
        }
    }

    close(ends[0]);
    int state = 0;
    if (waitpid(child, &state, 0) != child || !WIFEXITED(state) || WEXITSTATUS(state) || size > limit || failed) {
        free(data);
        return -1;
    }

    data[size] = 0;
    *output = (Bytes){data, size};
    return 0;
}

static int has_suffix(const char *value, const char *suffix) {
    size_t a = strlen(value), b = strlen(suffix);
    return a >= b && !memcmp(value + a - b, suffix, b);
}

static int read_license(const char *path, Bytes *sinf) {
    if (!has_suffix(path, ".ipa")) {
        return read_file(path, sinf);
    }

    Bytes listing = {0};
    char *list_args[] = {"/usr/bin/unzip", "-Z1", (char *)path, NULL};
    if (capture_child(list_args[0], list_args, 4 * 1024 * 1024, &listing)) {
        return -1;
    }

    Bytes chosen = {0};
    uint8_t account[4] = {0}, index[4] = {0};
    int matches = 0, status = -1;
    for (char *member = (char *)listing.data; *member;) {
        char *end = strchr(member, '\n');
        if (end) {
            *end = 0;
        }

        if (strstr(member, "/SC_Info/") && has_suffix(member, ".sinf") && !has_suffix(member, ".v4.sinf")) {
            Bytes candidate = {0}, user = {0}, key = {0};
            char *extract_args[] = {"/usr/bin/unzip", "-p", (char *)path, member, NULL};
            if (capture_child(extract_args[0], extract_args, 1024 * 1024, &candidate) || atom_field(candidate, "user", &user) || atom_field(candidate, "key ", &key) || user.size != 4 || key.size != 4) {
                free(candidate.data);
                goto end;
            }

            if (!matches) {
                memcpy(account, user.data, 4);
                memcpy(index, key.data, 4);
                chosen = candidate;
            } else {
                if (memcmp(account, user.data, 4) || memcmp(index, key.data, 4)) {
                    fprintf(stderr, "IPA has distinct license selectors; "
                                    "provide a specific SINF\n");
                    free(candidate.data);
                    goto end;
                }

                free(candidate.data);
            }

            matches++;
        }

        if (!end) {
            break;
        }

        member = end + 1;
    }

    if (!matches) {
        fprintf(stderr, "IPA contains no supported SINF\n");
        goto end;
    }

    *sinf = chosen;
    chosen = (Bytes){0};
    status = 0;
end:
    free(chosen.data);
    free(listing.data);
    return status;
}

static int temp_path(const char *directory, const char *name, char output[PATH_MAX]) {
    int written = snprintf(output, PATH_MAX, "%s/%s", directory, name);
    return written > 0 && written < PATH_MAX ? 0 : -1;
}

typedef struct {
    uint8_t key[16];
    size_t length;
    Bytes uid;
} UIDLayerScan;

static int scan_uid_candidate(vm_map_t task, vm_address_t address, UIDLayerScan *scan) {
    uint8_t *data = malloc(scan->length);
    if (!data) {
        return -1;
    }

    vm_size_t got = 0;
    kern_return_t status = vm_read_overwrite(task, address, scan->length, (vm_address_t)(uintptr_t)data, &got);
    if (status != KERN_SUCCESS || got != scan->length) {
        free(data);
        return 0;
    }

    Bytes clear = {0};
    uint8_t udid[20];
    int valid = !device_udid(udid) && !keybag_clear_from_uid_layer((Bytes){data, scan->length}, udid, &clear) && clear.size >= 32 && !memcmp(clear.data, "\0\0\0\0\0\0\0\0\0\0\0\0", 12) && be32(clear.data + 12) >= 20 && be32(clear.data + 12) <= clear.size - 12 && !memcmp(clear.data + 16, "sean", 4);
    if (clear.data) {
        memset(clear.data, 0, clear.size);
        free(clear.data);
    }

    memset(udid, 0, sizeof(udid));
    if (!valid) {
        free(data);
        return 0;
    }

    scan->uid = (Bytes){data, scan->length};
    return 1;
}

static int scan_uid_region(vm_map_t task, vm_address_t start, vm_size_t size, UIDLayerScan *scan, uint64_t *bytes_read) {
    uint8_t *buffer = malloc(65536 + 15);
    uint8_t *decoded = malloc(65536 + 15);
    CCCryptorRef cipher = NULL;
    if (!buffer || !decoded || CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, scan->key, sizeof(scan->key), NULL, &cipher) != kCCSuccess) {
        free(buffer);
        free(decoded);
        return -1;
    }

    int found = 0;
    size_t carry = 0;
    for (vm_size_t offset = 0; offset < size;) {
        vm_size_t chunk = size - offset;
        if (chunk > 65536) {
            chunk = 65536;
        }

        vm_size_t got = 0;
        kern_return_t status = vm_read_overwrite(task, start + offset, chunk, (vm_address_t)(uintptr_t)(buffer + carry), &got);
        if (status != KERN_SUCCESS || got != chunk) {
            carry = 0;
            offset += chunk;
            continue;
        }

        *bytes_read += got;
        size_t available = carry + got;
        vm_address_t first = start + offset - carry;
        for (size_t phase = 0; phase < 16 && phase + 16 <= available; phase++) {
            size_t length = (available - phase) & ~(size_t)15;
            size_t written = 0;
            if (CCCryptorUpdate(cipher, buffer + phase, length, decoded, 65536 + 15, &written) != kCCSuccess || written != length) {
                found = -1;
                goto end;
            }

            for (size_t at = 0; at + 16 <= written; at += 16) {
                if (memcmp(decoded + at, KEYBAG_IV, 12)) {
                    continue;
                }

                vm_address_t candidate = first + phase + at;
                int result = scan_uid_candidate(task, candidate, scan);
                if (result) {
                    found = result;
                    goto end;
                }
            }
        }

        carry = available < 15 ? available : 15;
        memmove(buffer, buffer + available - carry, carry);
        offset += chunk;
    }

end:
    CCCryptorRelease(cipher);
    free(buffer);
    free(decoded);
    return found;
}

static int scan_uid_task(vm_map_t task, UIDLayerScan *scan, uint64_t *bytes_read) {
    vm_address_t address = 0;
    for (unsigned regions = 0; regions < 16384; regions++) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t status = vm_region_64(task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), object);
        }

        if (status != KERN_SUCCESS) {
            return 0;
        }

        if (!size || address > UINTPTR_MAX - size) {
            return -1;
        }

        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE) && !info.shared && size <= 128 * 1024 * 1024 && *bytes_read < 256 * 1024 * 1024) {
            int found = scan_uid_region(task, address, size, scan, bytes_read);
            if (found) {
                return found;
            }
        }

        address += size;
    }

    return -1;
}

static int observe_uid_callback(mach_port_t task, void *opaque) {
    UIDLayerScan *scan = opaque;
    uint64_t bytes_read = 0;
    return scan_uid_task(task, scan, &bytes_read);
}

static int fairplay_selector(uint32_t *selector) {
    struct utsname system_info;
    if (uname(&system_info)) {
        return -1;
    }

    char *end = NULL;
    errno = 0;
    unsigned long major = strtoul(system_info.release, &end, 10);
    if (errno || end == system_info.release || (*end != '.' && *end != '\0')) {
        return -1;
    }

    *selector = major <= 19 ? 9 : 21;
    return 0;
}

static int run_observe_uid_layer(int argc, char **argv) {
    if ((argc != 4 && argc != 5) || access(argv[3], F_OK) == 0) {
        return 2;
    }

    unsigned seconds = 120;
    if (argc == 5) {
        char *timeout_end = NULL;
        errno = 0;
        unsigned long requested = strtoul(argv[4], &timeout_end, 10);
        if (errno || !timeout_end || *timeout_end || requested == 0 || requested > 600) {
            return 2;
        }

        seconds = (unsigned)requested;
    }

    char *end = NULL;
    errno = 0;
    long parsed = strtol(argv[2], &end, 10);
    if (errno || !end || *end || parsed <= 0 || parsed > INT_MAX) {
        return 2;
    }

    uint32_t selector;
    if (fairplay_selector(&selector)) {
        fprintf(stderr, "cannot determine FairPlay selector\n");
        return 1;
    }

    const char *sidb_name = "/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sidb";
    Bytes sidb = {0};
    UIDLayerScan scan = {0};
    uint8_t udid[20];
    int result = 1;
    if (read_file(sidb_name, &sidb) || sidb.size < 36 || (sidb.size - 20) % 16 || memcmp(sidb.data, "\x80\x06\x00\x03", 4) || device_udid(udid) || descriptor_key(udid, scan.key)) {
        goto end;
    }

    scan.length = sidb.size - 20;
    int found = observe_fairplay_requests((pid_t)parsed, selector, observe_uid_callback, &scan, seconds);
    if (found == 1 && !write_new(argv[3], scan.uid.data, scan.uid.size)) {
        result = 0;
    }

end:
    free(sidb.data);
    if (scan.uid.data) {
        memset(scan.uid.data, 0, scan.uid.size);
        free(scan.uid.data);
    }

    memset(scan.key, 0, sizeof(scan.key));
    memset(udid, 0, sizeof(udid));
    return result;
}

static int run_retrieve(int argc, char **argv) {
    if (argc != 4 && argc != 5) {
        return 2;
    }

    const char *output = argc == 5 ? argv[4] : "credential.bin";
    if (access(output, F_OK) == 0) {
        fprintf(stderr, "output already exists: %s\n", output);
        return 1;
    }

    const char *sidb_name = "/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sidb";
    char helper[PATH_MAX], table_name[PATH_MAX], word_table_name[PATH_MAX];
    if (companion_path("driver.ios", helper) || companion_path("static-key-table.bin", table_name) || companion_path("core4-word-table.bin", word_table_name)) {
        fprintf(stderr, "cannot locate companion files\n");
        return 1;
    }

    uint32_t selector;
    if (fairplay_selector(&selector)) {
        fprintf(stderr, "cannot determine FairPlay selector\n");
        return 1;
    }

    char *selector_text = selector == 9 ? "9" : "21";
    Bytes sinf = {0}, sidb = {0}, table = {0}, word_table = {0};
    Bytes uid_layer = {0}, clear = {0}, artifact = {0};
    Selection selected = {0};
    uint8_t udid[20], request[552], core3_block[16], context[16];
    uint8_t credential[16];
    char directory[PATH_MAX] = {0};
    char source_path[PATH_MAX] = {0};
    char request_paths[3][PATH_MAX] = {{0}};
    char artifact_paths[3][PATH_MAX] = {{0}};
    int created = 0, status = 1;
    const char *stage = "license input";
    if (read_license(argv[2], &sinf)) {
        goto end;
    }

    Bytes encrypted_priv = {0};
    if (atom_field(sinf, "priv", &encrypted_priv) || (encrypted_priv.size != 448 && !(encrypted_priv.size == 440 && !memcmp(encrypted_priv.data + 432, "\0\0\0\0\0\0\0\0", 8)))) {
        fprintf(stderr, "unsupported SINF priv layout: %zu bytes\n", encrypted_priv.size);
        goto end;
    }

    stage = "device SIDB";
    if (read_file(sidb_name, &sidb) || sidb.size < 36 || (sidb.size - 20) % 16 || memcmp(sidb.data, "\x80\x06\x00\x03", 4)) {
        goto end;
    }

    stage = "static key table";
    if (read_file(table_name, &table) || table.size != TABLE_SIZE) {
        goto end;
    }

    stage = "core-4 word table";
    if (read_file(word_table_name, &word_table) || word_table.size != CORE4_WORD_TABLE_SIZE) {
        goto end;
    }

    stage = "device identifier and license selector";
    if (device_udid(udid) || atom_field(sinf, "user", &(Bytes){0}) || atom_field(sinf, "key ", &(Bytes){0})) {
        goto end;
    }

    stage = "temporary workspace";
    int length = snprintf(directory, sizeof(directory), "/var/tmp/fp-credential-XXXXXX");
    if (length <= 0 || length >= (int)sizeof(directory) || !mkdtemp(directory)) {
        goto end;
    }

    created = 1;
    if (temp_path(directory, "source16.bin", source_path)) {
        goto end;
    }

    stage = "SIDB decryption and license selection";
    if (read_file(argv[3], &uid_layer) || uid_layer.size != sidb.size - 20 || keybag_clear_from_uid_layer(uid_layer, udid, &clear)) {
        goto end;
    }

    if (select_license(clear, sinf, &selected) || write_new(source_path, selected.session, 16)) {
        goto end;
    }

    for (unsigned attempt = 0; attempt < 3; attempt++) {
        stage = "driver request construction";
        uint64_t slot = UINT64_C(0x16b000000) + (uint64_t)arc4random_uniform(0x4000) * 0x4000 + 0x14f0;
        if (selector_request(&selected, slot + 0x180, request)) {
            goto end;
        }

        char filename[32], slot_text[32];
        snprintf(filename, sizeof(filename), "request-%u.bin", attempt);
        if (temp_path(directory, filename, request_paths[attempt]) || write_new(request_paths[attempt], request, sizeof(request))) {
            goto end;
        }

        snprintf(filename, sizeof(filename), "artifact-%u.bin", attempt);
        if (temp_path(directory, filename, artifact_paths[attempt])) {
            goto end;
        }

        snprintf(slot_text, sizeof(slot_text), "%#llx", (unsigned long long)slot);
        char *helper_args[] = {helper, request_paths[attempt], artifact_paths[attempt], source_path, slot_text, selector_text, NULL};
        stage = "FairPlay driver call";
        int result = run_child(helper, helper_args);
        if (result == 8) {
            continue;
        }

        if (result || read_file(artifact_paths[attempt], &artifact) || artifact.size != 920) {
            goto end;
        }

        for (size_t i = 0; i < 0x160; i++) {
            if (artifact.data[i] != 'Z') {
                goto end;
            }
        }

        stage = "credential derivation";
        if (core3(&selected, artifact.data + 904, core3_block) || core4_context(sinf, udid, word_table.data, context) || finish_credential(core3_block, context, table.data, credential) || write_new(output, credential, sizeof(credential))) {
            goto end;
        }
        status = 0;
        break;
    }

end:
    if (status) {
        fprintf(stderr, "retrieval failed at %s\n", stage);
    }

    if (source_path[0]) {
        unlink(source_path);
    }

    for (size_t i = 0; i < 3; i++) {
        if (request_paths[i][0]) {
            unlink(request_paths[i]);
        }

        if (artifact_paths[i][0]) {
            unlink(artifact_paths[i]);
        }
    }

    if (created) {
        rmdir(directory);
    }

    free(sinf.data);
    free(sidb.data);
    free(table.data);
    free(word_table.data);
    free(uid_layer.data);
    free(clear.data);
    free(artifact.data);
    memset(core3_block, 0, sizeof(core3_block));
    memset(context, 0, sizeof(context));
    memset(credential, 0, sizeof(credential));
    return status;
}

int main(int argc, char **argv) {
    int status = -1;
    if (argc >= 2 && !strcmp(argv[1], "retrieve")) {
        status = run_retrieve(argc, argv);
    } else if (argc >= 2 && !strcmp(argv[1], "device-udid")) {
        status = run_device_udid(argc, argv);
    } else if (argc >= 2 && !strcmp(argv[1], "observe-uid-layer")) {
        status = run_observe_uid_layer(argc, argv);
    }

    if (status && (argc < 2 || (strcmp(argv[1], "retrieve") && strcmp(argv[1], "device-udid") && strcmp(argv[1], "observe-uid-layer")) || status == 2)) {
        fprintf(stderr,
                "usage: %s retrieve IPA_OR_SINF UID_LAYER [NEW_CREDENTIAL]\n"
                "       %s device-udid NEW_FILE\n"
                "       %s observe-uid-layer PID NEW_UID_LAYER [TIMEOUT_SECONDS]\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }

    return status;
}
