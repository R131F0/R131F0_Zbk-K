/**
 * @file engine.h
 * @brief Core engine for Ptrace event loop and Gadget Redirection.
 */

#ifndef ENGINE_H
#define ENGINE_H

#include "injector.h"

// Public API
InjectorStatus wait_and_handle_events(int pid, int *out_status);
InjectorStatus wait_for_initial_stop(int pid);
InjectorStatus remote_syscall(int pid, long *out_result, long sysno, ...);

#endif // ENGINE_H
