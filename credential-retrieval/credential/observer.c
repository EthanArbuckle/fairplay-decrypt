#include "observer.h"
#include <mach/arm/thread_status.h>
#include <mach/exc.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { MAX_THREADS = 256 };
enum { USER_BREAKPOINT = 0x1e5 };

typedef struct {
    thread_t port;
    arm_debug_state64_t saved;
    int saved_valid;
    uint64_t return_address;
    int matched_selector;
} ThreadWatch;

typedef struct {
    task_t task;
    mach_port_t exception_port;
    uint64_t call_address;
    uint32_t selector;
    SelectorReturnCallback callback;
    EntryCallback entry_callback;
    void *context;
    ThreadWatch threads[MAX_THREADS];
    size_t thread_count;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_handlers[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count;
    int handler_installed;
    int result;
} Observer;

static Observer *active_observer;
static volatile sig_atomic_t observer_stopped;
extern boolean_t exc_server(mach_msg_header_t *request, mach_msg_header_t *reply);

static void stop_observer(int signal_number) {
    (void)signal_number;
    observer_stopped = 1;
}

/* Call only while the target thread is stopped (task suspension or exception).
 * XNU 8792 can mutate DebugData in place without reloading a remote CPU's
 * debug registers: the EL0-return path compares DebugData pointers. Clearing
 * every enable bit first releases the thread's old object; installing the
 * desired state then forces a fresh object and a hardware-register reload.
 * Preserve all saved slots in the final state, including other debuggers'
 * watchpoints.
 */
static kern_return_t replace_debug_state(thread_t thread, const arm_debug_state64_t *desired) {
    arm_debug_state64_t cleared = {0};
    kern_return_t status = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&cleared, ARM_DEBUG_STATE64_COUNT);
    if (status != KERN_SUCCESS) {
        return status;
    }
    return thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)desired, ARM_DEBUG_STATE64_COUNT);
}

static int set_breakpoints(ThreadWatch *watch, uint64_t call_address, uint64_t return_address) {
    arm_debug_state64_t state = watch->saved;
    state.__bvr[0] = call_address;
    state.__bcr[0] = return_address ? 0 : USER_BREAKPOINT;
    state.__bvr[1] = return_address;
    state.__bcr[1] = return_address ? USER_BREAKPOINT : 0;
    return replace_debug_state(watch->port, &state) == KERN_SUCCESS ? 0 : -1;
}

kern_return_t catch_exception_raise(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count) {
    (void)code;
    (void)code_count;
    Observer *observer = active_observer;
    if (!observer || exception_port != observer->exception_port || task != observer->task || exception != EXC_BREAKPOINT) {
        return KERN_FAILURE;
    }

    ThreadWatch *watch = NULL;
    for (size_t i = 0; i < observer->thread_count; i++) {
        if (observer->threads[i].port == thread) {
            watch = &observer->threads[i];
            break;
        }
    }

    if (!watch) {
        return KERN_FAILURE;
    }

    arm_thread_state64_t state = {0};
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count) != KERN_SUCCESS) {
        return KERN_FAILURE;
    }

    uint64_t pc = (uint64_t)(uintptr_t)arm_thread_state64_get_pc(state);
    if (watch->port == MACH_PORT_NULL) {
        observer->result = -1;
        observer_stopped = 1;
        return KERN_FAILURE;
    }

    if (pc == observer->call_address && !watch->return_address) {
        if (observer->entry_callback) {
            int result = observer->entry_callback(observer->task, state.__x[0], observer->context);
            if (result) {
                observer->result = result;
                observer_stopped = 1;
            }
        }

        watch->matched_selector = !observer->entry_callback && state.__x[1] == observer->selector;
        watch->return_address = (uint64_t)(uintptr_t)arm_thread_state64_get_lr(state);
        if (!watch->return_address || set_breakpoints(watch, observer->call_address, watch->return_address)) {
            observer->result = -1;
            observer_stopped = 1;
            return KERN_FAILURE;
        }

        return KERN_SUCCESS;
    }

    if (pc == watch->return_address && watch->return_address) {
        watch->return_address = 0;
        if (set_breakpoints(watch, observer->call_address, 0)) {
            observer->result = -1;
            observer_stopped = 1;
            return KERN_FAILURE;
        }

        if (watch->matched_selector) {
            int result = observer->callback(observer->task, observer->context);
            if (result) {
                observer->result = result;
                observer_stopped = 1;
            }
        }

        return KERN_SUCCESS;
    }

    return KERN_FAILURE;
}

kern_return_t catch_exception_raise_state(mach_port_t exception_port, exception_type_t exception, const exception_data_t code, mach_msg_type_number_t code_count, int *flavor, const thread_state_t old_state, mach_msg_type_number_t old_count, thread_state_t new_state, mach_msg_type_number_t *new_count) {
    (void)exception_port;
    (void)exception;
    (void)code;
    (void)code_count;
    (void)flavor;
    (void)old_state;
    (void)old_count;
    (void)new_state;
    (void)new_count;
    return KERN_FAILURE;
}

kern_return_t catch_exception_raise_state_identity(mach_port_t exception_port, mach_port_t thread, mach_port_t task, exception_type_t exception, exception_data_t code, mach_msg_type_number_t code_count, int *flavor, thread_state_t old_state, mach_msg_type_number_t old_count, thread_state_t new_state, mach_msg_type_number_t *new_count) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)code_count;
    (void)flavor;
    (void)old_state;
    (void)old_count;
    (void)new_state;
    (void)new_count;
    return KERN_FAILURE;
}

static void restore_observer(Observer *observer) {
    if (observer->task != MACH_PORT_NULL) {
        int suspended = task_suspend(observer->task) == KERN_SUCCESS;
        for (size_t i = 0; i < observer->thread_count; i++) {
            ThreadWatch *watch = &observer->threads[i];
            if (watch->saved_valid) {
                replace_debug_state(watch->port, &watch->saved);
            }
            mach_port_deallocate(mach_task_self(), watch->port);
        }

        if (observer->handler_installed) {
            for (mach_msg_type_number_t i = 0; i < observer->old_count; i++) {
                task_set_exception_ports(observer->task, observer->old_masks[i], observer->old_handlers[i], observer->old_behaviors[i], observer->old_flavors[i]);
                if (observer->old_handlers[i] != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), observer->old_handlers[i]);
                }
            }

            if (observer->old_count == 0) {
                task_set_exception_ports(observer->task, EXC_MASK_BREAKPOINT, MACH_PORT_NULL, EXCEPTION_DEFAULT, ARM_THREAD_STATE64);
            }
        }

        if (suspended) {
            task_resume(observer->task);
        }

        mach_port_deallocate(mach_task_self(), observer->task);
    }

    if (observer->exception_port != MACH_PORT_NULL) {
        mach_port_destroy(mach_task_self(), observer->exception_port);
    }
}

static int read_remote(task_t task, uint64_t address, void *buffer, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(task, (vm_address_t)address, size, (vm_address_t)(uintptr_t)buffer, &got) == KERN_SUCCESS && got == size ? 0 : -1;
}

static int main_image_base(task_t task, uint64_t *base) {
    task_dyld_info_data_t info = {0};
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    struct dyld_all_image_infos images = {0};
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS || read_remote(task, info.all_image_info_addr, &images, sizeof(images)) || images.infoArrayCount > 4096) {
        return -1;
    }

    for (uint32_t i = 0; i < images.infoArrayCount; i++) {
        struct dyld_image_info image = {0};
        if (read_remote(task, (uint64_t)(uintptr_t)images.infoArray + (uint64_t)i * sizeof(image), &image, sizeof(image))) {
            return -1;
        }

        struct mach_header_64 header = {0};
        if (read_remote(task, (uint64_t)(uintptr_t)image.imageLoadAddress, &header, sizeof(header))) {
            continue;
        }

        if (header.magic == MH_MAGIC_64 && header.filetype == MH_EXECUTE) {
            *base = (uint64_t)(uintptr_t)image.imageLoadAddress;
            return 0;
        }
    }

    return -1;
}

static uint32_t instruction(const uint8_t *data) {
    uint32_t word;
    memcpy(&word, data, sizeof(word));
    return word;
}

static int credential_transform_candidate_original(const uint8_t *code, size_t remaining) {
    static const uint8_t prologue[] = {
        0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9,
        0xf4, 0x4f, 0x04, 0xa9, 0xfd, 0x7b, 0x05, 0xa9, 0xfd, 0x43, 0x01, 0x91, 0xff, 0x43, 0x12, 0xd1,
    };
    if (remaining < 0x1500 || memcmp(code, prologue, sizeof(prologue))) {
        return 0;
    }

    uint32_t saved = 0;
    for (size_t at = sizeof(prologue); at < 0x180; at += 4) {
        uint32_t word = instruction(code + at);
        if ((word & 0xffffffe0) == 0xaa0003e0) {
            saved |= 1U << (word & 31);
        }
    }

    for (size_t at = sizeof(prologue); at < 0x1500; at += 4) {
        uint32_t word = instruction(code + at);
        if ((word & 0xfffffc00) == 0xf9401800 && (saved & (1U << ((word >> 5) & 31)))) {
            return 1;
        }
    }

    return 0;
}

static int credential_transform_candidate_context(const uint8_t *code, size_t remaining) {
    static const uint8_t prologue[] = {
        0xfc, 0x6f, 0xba, 0xa9, 0xfa, 0x67, 0x01, 0xa9, 0xf8, 0x5f, 0x02, 0xa9, 0xf6, 0x57, 0x03, 0xa9,
        0xf4, 0x4f, 0x04, 0xa9, 0xfd, 0x7b, 0x05, 0xa9, 0xfd, 0x43, 0x01, 0x91,
    };
    if (remaining < 0x180 || memcmp(code, prologue, sizeof(prologue))) {
        return 0;
    }

    if ((instruction(code + 28) & 0xffc003ff) != 0xd10003ff || instruction(code + 32) != 0xaa0003fb) {
        return 0;
    }

    int reads_length = 0, reads_priv = 0;
    for (size_t at = 36; at < 0x180; at += 4) {
        uint32_t word = instruction(code + at);
        reads_length |= (word & 0xffffffe0) == 0xb9400c00;
        reads_priv |= (word & 0xffff83e0) == 0xa9420000 || (word & 0xffffffe0) == 0xf9401000;
    }

    return reads_length && reads_priv;
}

static int credential_transform_address(task_t task, uint64_t base, uint64_t *address) {
    struct mach_header_64 header = {0};
    if (read_remote(task, base, &header, sizeof(header)) || header.magic != MH_MAGIC_64 || header.filetype != MH_EXECUTE || header.ncmds > 4096 || header.sizeofcmds > 1024 * 1024) {
        return -1;
    }

    uint8_t *commands = malloc(header.sizeofcmds);
    if (!commands || read_remote(task, base + sizeof(header), commands, header.sizeofcmds)) {
        free(commands);
        return -1;
    }

    uint64_t image_vmaddr = 0, text_vmaddr = 0, text_size = 0;
    size_t at = 0;
    for (uint32_t i = 0; i < header.ncmds; i++) {
        if (at + sizeof(struct load_command) > header.sizeofcmds) {
            break;
        }

        struct load_command *command = (struct load_command *)(void *)(commands + at);
        if (command->cmdsize < sizeof(*command) || command->cmdsize > header.sizeofcmds - at) {
            break;
        }

        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            struct segment_command_64 *segment = (struct segment_command_64 *)(void *)command;
            if (!strncmp(segment->segname, "__TEXT", sizeof(segment->segname))) {
                image_vmaddr = segment->vmaddr;
            }

            if (segment->nsects <= (command->cmdsize - sizeof(*segment)) / sizeof(struct section_64)) {
                struct section_64 *sections = (struct section_64 *)(void *)(segment + 1);
                for (uint32_t j = 0; j < segment->nsects; j++) {
                    if (!strncmp(sections[j].sectname, "__text", sizeof(sections[j].sectname)) && sections[j].size <= 64 * 1024 * 1024) {
                        text_vmaddr = sections[j].addr;
                        text_size = sections[j].size;
                    }
                }
            }
        }

        at += command->cmdsize;
    }

    free(commands);
    if (!image_vmaddr || text_vmaddr < image_vmaddr || text_size < 0x1500 || text_vmaddr - image_vmaddr > UINT64_MAX - base) {
        return -1;
    }

    uint64_t runtime_text = base + text_vmaddr - image_vmaddr;
    uint8_t *code = malloc((size_t)text_size);
    if (!code) {
        return -1;
    }

    for (uint64_t offset = 0; offset < text_size; offset += 65536) {
        size_t length = (size_t)(text_size - offset);
        if (length > 65536) {
            length = 65536;
        }

        if (read_remote(task, runtime_text + offset, code + offset, length)) {
            free(code);
            return -1;
        }
    }

    unsigned original_matches = 0, context_matches = 0;
    uint64_t original_address = 0, context_address = 0;
    for (uint64_t offset = 0; offset + 0x1500 <= text_size; offset += 4) {
        if (credential_transform_candidate_original(code + offset, (size_t)(text_size - offset))) {
            original_address = runtime_text + offset;
            original_matches++;
        }

        if (credential_transform_candidate_context(code + offset, (size_t)(text_size - offset))) {
            context_address = runtime_text + offset;
            context_matches++;
        }
    }

    free(code);
    if (context_matches == 1) {
        *address = context_address;
        return 0;
    }

    if (context_matches == 0 && original_matches == 1) {
        *address = original_address;
        return 0;
    }

    return -1;
}

static int observe_fairplay(pid_t pid, uint32_t selector, SelectorReturnCallback callback, EntryCallback entry_callback, void *context, unsigned seconds) {
    Observer *observer = calloc(1, sizeof(*observer));
    if (!observer || seconds == 0 || (entry_callback ? callback != NULL : (!callback || (selector != 9 && selector != 21)))) {
        free(observer);
        return -1;
    }

    observer->selector = selector;
    observer->callback = callback;
    observer->entry_callback = entry_callback;
    observer->context = context;
    observer->task = MACH_PORT_NULL;
    observer->exception_port = MACH_PORT_NULL;
    observer->result = 0;
    int outcome = -1;
    kern_return_t status = task_for_pid(mach_task_self(), pid, &observer->task);
    if (status != KERN_SUCCESS || observer->task == MACH_PORT_NULL) {
        fprintf(stderr, "task_for_pid(%d) failed: %#x\n", pid, status);
        goto end;
    }

    if (entry_callback) {
        uint64_t base = 0;
        if (main_image_base(observer->task, &base) || credential_transform_address(observer->task, base, &observer->call_address)) {
            fprintf(stderr, "cannot locate FairPlay credential transform\n");
            goto end;
        }
    } else {
        void *symbol = dlsym(RTLD_DEFAULT, "IOConnectCallStructMethod");
        uint8_t remote[16];
        if (!symbol || read_remote(observer->task, (uint64_t)(uintptr_t)symbol, remote, sizeof(remote)) || memcmp(remote, symbol, sizeof(remote))) {
            fprintf(stderr, "IOKit function is not mapped at the same address in fairplayd\n");
            goto end;
        }

        observer->call_address = (uint64_t)(uintptr_t)symbol;
    }

    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &observer->exception_port) != KERN_SUCCESS || mach_port_insert_right(mach_task_self(), observer->exception_port, observer->exception_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        goto end;
    }

    if (task_suspend(observer->task) != KERN_SUCCESS) {
        goto end;
    }

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    status = task_threads(observer->task, &threads, &count);
    if (status != KERN_SUCCESS || count > MAX_THREADS) {
        if (threads) {
            vm_deallocate(mach_task_self(), (vm_address_t)(uintptr_t)threads, count * sizeof(thread_t));
        }

        task_resume(observer->task);
        goto end;
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        ThreadWatch *watch = &observer->threads[observer->thread_count++];
        watch->port = threads[i];
        mach_msg_type_number_t state_count = ARM_DEBUG_STATE64_COUNT;
        status = thread_get_state(watch->port, ARM_DEBUG_STATE64, (thread_state_t)&watch->saved, &state_count);
        if (status != KERN_SUCCESS) {
            fprintf(stderr, "cannot read debug state for thread %u: %#x\n", watch->port, status);
            break;
        }

        watch->saved_valid = 1;
        if (watch->saved.__bcr[0] || watch->saved.__bcr[1]) {
            fprintf(stderr, "debug breakpoint slots 0 and 1 are in use\n");
            status = KERN_FAILURE;
            break;
        }

        status = set_breakpoints(watch, observer->call_address, 0) ? KERN_FAILURE : KERN_SUCCESS;
        if (status != KERN_SUCCESS) {
            fprintf(stderr, "cannot set user breakpoint on thread %u\n", watch->port);
            break;
        }
    }

    for (mach_msg_type_number_t i = (mach_msg_type_number_t)observer->thread_count; i < count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)(uintptr_t)threads, count * sizeof(thread_t));
    if (status != KERN_SUCCESS) {
        task_resume(observer->task);
        goto end;
    }

    observer->old_count = EXC_TYPES_COUNT;
    status = task_swap_exception_ports(observer->task, EXC_MASK_BREAKPOINT, observer->exception_port, EXCEPTION_DEFAULT, ARM_THREAD_STATE64, observer->old_masks, &observer->old_count, observer->old_handlers, observer->old_behaviors, observer->old_flavors);
    if (status != KERN_SUCCESS) {
        fprintf(stderr, "cannot install breakpoint exception handler: %#x\n", status);
        task_resume(observer->task);
        goto end;
    }

    observer->handler_installed = 1;
    active_observer = observer;
    observer_stopped = 0;
    struct sigaction action = {0}, old_int = {0}, old_term = {0}, old_alarm = {0};
    action.sa_handler = stop_observer;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &old_int);
    sigaction(SIGTERM, &action, &old_term);
    sigaction(SIGALRM, &action, &old_alarm);
    task_resume(observer->task);
    alarm(seconds);
    if (entry_callback) {
        fprintf(stderr, "observing FairPlay credential transform in pid %d for up to %u seconds\n", pid, seconds);
    } else {
        fprintf(stderr, "observing FairPlay requests with selector %u in pid %d for up to %u seconds\n", selector, pid, seconds);
    }
    while (!observer_stopped) {
        mach_msg_return_t received = mach_msg_server_once(exc_server, 4096, observer->exception_port, MACH_RCV_INTERRUPT);
        if (received != MACH_MSG_SUCCESS && received != MACH_RCV_INTERRUPTED) {
            fprintf(stderr, "exception receive failed: %#x\n", received);
            break;
        }
    }

    alarm(0);
    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    sigaction(SIGALRM, &old_alarm, NULL);
    outcome = observer->result;
    active_observer = NULL;

end:
    restore_observer(observer);
    free(observer);
    return outcome;
}

int observe_fairplay_requests(pid_t pid, uint32_t selector, SelectorReturnCallback callback, void *context, unsigned seconds) {
    return observe_fairplay(pid, selector, callback, NULL, context, seconds);
}

int observe_fairplay_credential(pid_t pid, EntryCallback callback, void *context, unsigned seconds) {
    return observe_fairplay(pid, 0, NULL, callback, context, seconds);
}
