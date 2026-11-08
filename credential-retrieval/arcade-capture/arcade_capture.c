#include "../credential/observer.h"
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAX_CANDIDATES = 4096, MAX_STACK = 0x20000, MAX_SIDO = 0x10000, MAX_BLOCK_WRITES = 3 };

typedef struct {
    uint64_t address;
    uint8_t *before;
} Candidate;

typedef struct {
    const char *prefix;
    uint8_t *sido;
    size_t sido_size;
    uint8_t *stack;
    size_t stack_size;
    Candidate *candidates;
    size_t candidate_count;
    thread_t active_thread;
    uint64_t destination_address;
    size_t block_start;
    size_t block_length;
    unsigned block_writes;
    unsigned source_calls;
    size_t largest_destination_count;
} Capture;

static int read_remote(mach_port_t task, uint64_t address, void *buffer, size_t size) {
    vm_size_t read_size = 0;
    return vm_read_overwrite(task, (vm_address_t)address, size, (vm_address_t)(uintptr_t)buffer, &read_size) == KERN_SUCCESS && read_size == size ? 0 : -1;
}

static int write_new(const char *prefix, const char *suffix, const void *bytes, size_t size) {
    char path[1024];
    if (snprintf(path, sizeof(path), "%s.%s", prefix, suffix) >= (int)sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -1;
    }

    const uint8_t *cursor = bytes;
    size_t remaining = size;
    while (remaining) {
        ssize_t written = write(fd, cursor, remaining);
        if (written <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }

        cursor += written;
        remaining -= (size_t)written;
    }

    return close(fd) == 0 ? 0 : -1;
}

static int load_file(const char *path, uint8_t **bytes, size_t *size) {
    struct stat info;
    if (stat(path, &info) || info.st_size < 64 || info.st_size > MAX_SIDO) {
        return -1;
    }

    FILE *file = fopen(path, "rb");
    if (!file) {
        return -1;
    }

    uint8_t *data = malloc((size_t)info.st_size);
    if (!data || fread(data, 1, (size_t)info.st_size, file) != (size_t)info.st_size) {
        free(data);
        fclose(file);
        return -1;
    }

    fclose(file);
    *bytes = data;
    *size = (size_t)info.st_size;
    return 0;
}

static int save_stack(mach_port_t task, const arm_thread_state64_t *state, Capture *capture) {
    uint64_t sp = (uint64_t)(uintptr_t)arm_thread_state64_get_sp(*state);
    vm_address_t region = (vm_address_t)sp;
    vm_size_t length = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t status = vm_region_64(task, &region, &length, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object);
    }

    if (status != KERN_SUCCESS || sp < region || sp >= region + length || !(info.protection & VM_PROT_READ)) {
        return -1;
    }

    uint64_t start = sp - region < 0x1000 ? region : sp - 0x1000;
    size_t size = (size_t)(region + length - start);
    if (size > MAX_STACK) {
        size = MAX_STACK;
    }

    capture->stack = malloc(size);
    if (!capture->stack || read_remote(task, start, capture->stack, size)) {
        return -1;
    }

    capture->stack_size = size;
    return 0;
}

static int has_candidate(const Capture *capture, uint64_t address) {
    for (size_t index = 0; index < capture->candidate_count; index++) {
        if (capture->candidates[index].address == address) {
            return 1;
        }
    }

    return 0;
}

static int save_candidates(mach_port_t task, Capture *capture) {
    capture->candidates = calloc(MAX_CANDIDATES, sizeof(*capture->candidates));
    if (!capture->candidates) {
        return -1;
    }

    for (size_t offset = 0; offset + 8 <= capture->stack_size; offset += 8) {
        uint64_t pointer = 0;
        memcpy(&pointer, capture->stack + offset, sizeof(pointer));
        for (unsigned variant = 0; variant < 2; variant++) {
            uint64_t skip = variant ? capture->sido[4] + 4 : 0;
            if (pointer < skip) {
                continue;
            }

            uint64_t address = pointer - skip;
            if (address < 0x100000000 || address >= 0x8000000000 || (address & 15) || has_candidate(capture, address)) {
                continue;
            }

            if (capture->candidate_count == MAX_CANDIDATES) {
                return -1;
            }

            uint8_t *before = malloc(capture->sido_size);
            if (!before) {
                return -1;
            }

            if (read_remote(task, address, before, capture->sido_size)) {
                free(before);
                continue;
            }

            Candidate *candidate = &capture->candidates[capture->candidate_count++];
            candidate->address = address;
            candidate->before = before;
        }
    }

    return 0;
}

static void clear_call(Capture *capture) {
    for (size_t index = 0; index < capture->candidate_count; index++) {
        free(capture->candidates[index].before);
    }

    free(capture->candidates);
    free(capture->stack);
    capture->candidates = NULL;
    capture->candidate_count = 0;
    capture->stack = NULL;
    capture->stack_size = 0;
    capture->active_thread = MACH_PORT_NULL;
}

static int capture_call(mach_port_t task, thread_t thread, int returning, const arm_thread_state64_t *state, void *context) {
    Capture *capture = context;
    if (returning == 2) {
        if (thread != capture->active_thread || !capture->destination_address || capture->block_writes >= MAX_BLOCK_WRITES) {
            return -1;
        }

        uint8_t *block = malloc(capture->block_length);
        if (!block || read_remote(task, capture->destination_address + capture->block_start, block, capture->block_length)) {
            free(block);
            return -1;
        }

        char suffix[32];
        int length = snprintf(suffix, sizeof(suffix), "block%u", ++capture->block_writes);
        int result = length < 0 || length >= (int)sizeof(suffix) || write_new(capture->prefix, suffix, block, capture->block_length);
        free(block);
        return result ? -1 : capture->block_writes == MAX_BLOCK_WRITES;
    }

    if (!returning) {
        if (capture->active_thread != MACH_PORT_NULL || (state->__x[1] != 9 && state->__x[1] != 21)) {
            return 0;
        }

        if (save_stack(task, state, capture) || save_candidates(task, capture)) {
            fprintf(stderr, "cannot capture FairPlay call-time stack or buffers\n");
            return -1;
        }

        size_t sources = 0;
        for (size_t index = 0; index < capture->candidate_count; index++) {
            if (!memcmp(capture->candidates[index].before, capture->sido, capture->sido_size)) {
                sources++;
            }
        }

        if (sources != 1) {
            clear_call(capture);
            return 0;
        }

        capture->source_calls++;
        capture->active_thread = thread;
        return 1;
    }

    if (thread != capture->active_thread) {
        return -1;
    }

    if (state->__x[0] != KERN_SUCCESS) {
        fprintf(stderr, "FairPlay driver call failed: %#llx\n", (unsigned long long)state->__x[0]);
        return -1;
    }

    size_t source_count = 0;
    size_t destination_count = 0;
    uint64_t destination_address = 0;
    size_t expected_start = capture->sido[4] + 12;
    if (expected_start + 53 > capture->sido_size || (capture->sido_size - expected_start - 37) % 16) {
        fprintf(stderr, "unsupported FairPlay sidewrite length\n");
        return -1;
    }

    size_t block_length = capture->sido_size - expected_start - 37;
    usleep(100000);
    for (size_t index = 0; index < capture->candidate_count; index++) {
        Candidate *candidate = &capture->candidates[index];
        if (!memcmp(candidate->before, capture->sido, capture->sido_size)) {
            source_count++;
        }

        uint8_t *after = malloc(capture->sido_size);
        if (!after) {
            return -1;
        }

        if (read_remote(task, candidate->address, after, capture->sido_size)) {
            free(after);
            continue;
        }

        size_t changes = 0;
        size_t first_change = block_length;
        for (size_t offset = expected_start; offset < expected_start + block_length; offset++) {
            if (candidate->before[offset] != after[offset]) {
                if (first_change == block_length) {
                    first_change = offset - expected_start;
                }

                changes++;
            }
        }

        if (!memcmp(candidate->before, after, expected_start) && first_change < 16 && changes > block_length / 2) {
            destination_count++;
            destination_address = candidate->address;
        }

        free(after);
    }

    if (destination_count > capture->largest_destination_count) {
        capture->largest_destination_count = destination_count;
    }

    if (source_count != 1 || destination_count != 1) {
        clear_call(capture);
        return 0;
    }

    clear_call(capture);
    capture->active_thread = thread;
    capture->destination_address = destination_address;
    capture->block_start = expected_start;
    capture->block_length = block_length;
    if (observe_fairplay_write(thread, destination_address + expected_start + block_length - 1)) {
        fprintf(stderr, "cannot watch FairPlay buffer writes\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s FAIRPLAYD_PID SIDO_FILE OUTPUT_PREFIX TIMEOUT_SECONDS\n", argv[0]);
        return 2;
    }

    char *end = NULL;
    errno = 0;
    long pid = strtol(argv[1], &end, 10);
    if (errno || !end || *end || pid <= 0) {
        return 2;
    }

    errno = 0;
    unsigned long seconds = strtoul(argv[4], &end, 10);
    if (errno || !end || *end || seconds == 0 || seconds > 600) {
        return 2;
    }

    Capture capture = {.prefix = argv[3]};
    if (load_file(argv[2], &capture.sido, &capture.sido_size)) {
        fprintf(stderr, "cannot read SIDO\n");
        return 1;
    }

    int result = observe_fairplay_io((pid_t)pid, capture_call, &capture, (unsigned)seconds);
    clear_call(&capture);
    free(capture.sido);
    if (result == 1) {
        return 0;
    }

    if (result < 0) {
        fprintf(stderr, "FairPlay IOKit observer failed\n");
    } else if (!capture.source_calls) {
        fprintf(stderr, "no FairPlay IOKit call referenced the current SIDO\n");
    } else if (!capture.destination_address && capture.largest_destination_count > 1) {
        fprintf(stderr, "FairPlay driver destination was ambiguous (%zu candidates)\n", capture.largest_destination_count);
    } else if (!capture.destination_address) {
        fprintf(stderr, "FairPlay driver destination was not found after %u matched calls\n", capture.source_calls);
    } else {
        fprintf(stderr, "FairPlay block capture stopped after %u of %u write stages\n", capture.block_writes, MAX_BLOCK_WRITES);
    }

    return 1;
}
