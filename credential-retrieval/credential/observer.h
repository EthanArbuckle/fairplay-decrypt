#ifndef FP_OBSERVER_H
#define FP_OBSERVER_H

#include <mach/mach.h>
#include <stdint.h>
#include <sys/types.h>

typedef int (*SelectorReturnCallback)(mach_port_t task, void *context);
typedef int (*EntryCallback)(mach_port_t task, uint64_t argument, void *context);

int observe_fairplay_requests(pid_t pid, uint32_t selector, SelectorReturnCallback callback, void *context, unsigned seconds);
int observe_fairplay_credential(pid_t pid, EntryCallback callback, void *context, unsigned seconds);

#endif
