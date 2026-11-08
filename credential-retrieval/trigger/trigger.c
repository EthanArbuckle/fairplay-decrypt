/* Request FairPlay's first-use path without running or copying decrypted code. */
#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    uint64_t offset;
    uint64_t size;
} Slice;

static uint32_t big32(const uint8_t *data) {
    return (uint32_t)data[0] << 24 | (uint32_t)data[1] << 16 | (uint32_t)data[2] << 8 | data[3];
}

static uint64_t big64(const uint8_t *data) {
    return (uint64_t)big32(data) << 32 | big32(data + 4);
}

static int select_slice(const uint8_t *data, uint64_t size, Slice *slice) {
    if (size < sizeof(struct mach_header_64)) {
        return -1;
    }

    uint32_t magic;
    memcpy(&magic, data, sizeof(magic));
    if (magic == MH_MAGIC_64) {
        *slice = (Slice){0, size};
        return 0;
    }

    int fat64 = data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbf;
    if (!fat64 && !(data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe)) {
        return -1;
    }

    uint32_t count = big32(data + 4);
    uint64_t entry_size = fat64 ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
    if (!count || count > 256 || 8 + (uint64_t)count * entry_size > size) {
        return -1;
    }

    Slice first = {0};
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *entry = data + 8 + (uint64_t)i * entry_size;
        if (big32(entry) != CPU_TYPE_ARM64) {
            continue;
        }

        Slice candidate = fat64 ? (Slice){big64(entry + 8), big64(entry + 16)} : (Slice){big32(entry + 8), big32(entry + 12)};
        if (!candidate.size || candidate.offset > size || candidate.size > size - candidate.offset) {
            return -1;
        }

        if (!first.size) {
            first = candidate;
        }

        if ((big32(entry + 4) & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64_ALL) {
            *slice = candidate;
            return 0;
        }
    }

    if (!first.size) {
        return -1;
    }

    *slice = first;
    return 0;
}

static int encryption_info(const uint8_t *data, Slice slice, struct mach_header_64 *header, struct encryption_info_command_64 *encryption) {
    if (slice.size < sizeof(*header)) {
        return -1;
    }

    memcpy(header, data + slice.offset, sizeof(*header));
    if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64 || header->ncmds > 1024 || header->sizeofcmds > slice.size - sizeof(*header)) {
        return -1;
    }

    uint64_t at = slice.offset + sizeof(*header);
    uint64_t end = at + header->sizeofcmds;
    int found = 0;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (at + sizeof(struct load_command) > end) {
            return -1;
        }

        struct load_command command;
        memcpy(&command, data + at, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize > end - at) {
            return -1;
        }

        if (command.cmd == LC_ENCRYPTION_INFO_64) {
            if (found || command.cmdsize < sizeof(*encryption)) {
                return -1;
            }

            memcpy(encryption, data + at, sizeof(*encryption));
            found = 1;
        }

        at += command.cmdsize;
    }

    if (!found || !encryption->cryptid || !encryption->cryptsize || encryption->cryptoff > slice.size || encryption->cryptsize > slice.size - encryption->cryptoff) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s ENCRYPTED_EXECUTABLE\n", argv[0]);
        return 2;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open encrypted executable");
        return 1;
    }

    struct stat info;
    if (fstat(fd, &info) || info.st_size < (off_t)sizeof(struct mach_header_64) || (uint64_t)info.st_size > SIZE_MAX) {
        fprintf(stderr, "invalid executable size\n");
        close(fd);
        return 1;
    }

    size_t length = (size_t)info.st_size;
    uint8_t *mapping = mmap(NULL, length, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
        int denied = errno == EPERM;
        perror("mmap encrypted executable");
        close(fd);
        return denied ? 3 : 1;
    }

    Slice slice = {0};
    struct mach_header_64 header = {0};
    struct encryption_info_command_64 encryption = {0};
    int result = 1;
    if (select_slice(mapping, length, &slice) || encryption_info(mapping, slice, &header, &encryption)) {
        fprintf(stderr, "no supported encrypted arm64 slice\n");
        goto end;
    }

    uint8_t *encrypted = mapping + slice.offset + encryption.cryptoff;
    size_t page_size = (size_t)getpagesize();
    uintptr_t aligned_addr = (uintptr_t)encrypted & ~(uintptr_t)(page_size - 1);
    if (aligned_addr < (uintptr_t)(mapping + slice.offset)) {
        fprintf(stderr, "encrypted region is not page-aligned\n");
        goto end;
    }

    size_t lead = (size_t)((uintptr_t)encrypted - aligned_addr);
    size_t encrypted_length = (lead + (size_t)encryption.cryptsize + page_size - 1) & ~(page_size - 1);
    uint8_t *aligned = (uint8_t *)aligned_addr;
    if ((uintptr_t)aligned < (uintptr_t)(mapping + slice.offset) || encrypted_length > (size_t)((mapping + slice.offset + slice.size) - aligned)) {
        fprintf(stderr, "encrypted mapping exceeds the executable\n");
        goto end;
    }

    int (*remap)(void *, size_t, uint32_t, cpu_type_t, cpu_subtype_t) = dlsym(RTLD_DEFAULT, "mremap_encrypted");
    if (!remap) {
        fprintf(stderr, "mremap_encrypted is unavailable\n");
        goto end;
    }

    if (remap(aligned, encrypted_length, encryption.cryptid, header.cputype, header.cpusubtype)) {
        int denied = errno == EPERM;
        fprintf(stderr, "mremap_encrypted failed: %s\n", strerror(errno));
        result = denied ? 3 : 1;
        goto end;
    }

    result = 0;

end:
    munmap(mapping, length);
    close(fd);
    return result;
}
