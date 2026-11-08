#ifndef FP_OBSERVER_H
#define FP_OBSERVER_H

#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <stdint.h>
#include <sys/types.h>

typedef int (*SelectorReturnCallback)(mach_port_t task, void *context);
typedef int (*IOCallCallback)(mach_port_t task, thread_t thread, int returning, const arm_thread_state64_t *state, void *context);

int observe_fairplay_requests(pid_t pid, uint32_t selector, SelectorReturnCallback callback, void *context, unsigned seconds);
int observe_fairplay_io(pid_t pid, IOCallCallback callback, void *context, unsigned seconds);
int observe_fairplay_write(thread_t thread, uint64_t address);

#endif
