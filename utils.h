/**
 * @file utils.h
 * @brief Public API for low-level memory, register, and process utilities.
 */

#ifndef UTILS_H
#define UTILS_H

#include "injector.h"

void init_regs_wrapper(target_regs_wrapper *wrapper);

// Ptrace Register Access
InjectorStatus get_regs(int pid, target_regs_wrapper *wrapper);
InjectorStatus set_regs(int pid, target_regs_wrapper *wrapper);

// Memory Access
bool is_remote_error(long res);
InjectorStatus read_remote_chunk(int pid, unsigned long addr, void *buf, size_t len);
InjectorStatus write_remote_mem(int pid, unsigned long addr, void *buf, size_t len);

// Process Control
InjectorStatus waitpid_with_timeout(int pid, int *out_status, int timeout_ms);

#endif // UTILS_H
