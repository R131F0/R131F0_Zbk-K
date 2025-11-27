/**
 * @file injector.h
 * @brief Global configuration, types, and architecture definitions.
 *
 * This header acts as the "Single Source of Truth" for the project configuration.
 * It contains shared enums, macros, and global variable declarations.
 */

#ifndef INJECTOR_H
#define INJECTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <signal.h>
#include <time.h>
#include <android/log.h>
#include <stdarg.h> 

// ============================================================================
// LOGGING SYSTEM
// ============================================================================

#define TAG "SyscallInjector"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG, __VA_ARGS__)
#define PLOGE(fmt) LOGE(fmt ": %s (errno=%d)", strerror(errno), errno)

// ============================================================================
// GLOBAL CONFIGURATION
// ============================================================================

#define OPERATION_TIMEOUT_MS 2000 

/**
 * @enum InjectorStatus
 * @brief Standardized return codes for all injector operations.
 */
typedef enum {
    INJ_SUCCESS = 0,
    INJ_ERR_GENERIC = -1,
    INJ_ERR_PERMISSION = -2,        // Root required
    INJ_ERR_ATTACH = -3,            // Ptrace attach failed
    INJ_ERR_DETACH = -4,            // Ptrace detach failed
    INJ_ERR_SYSCALL_REDIRECT = -5,  // Remote syscall failed
    INJ_ERR_MEMORY_RW = -6,         // process_vm_writev/readv failed
    INJ_ERR_TIMEOUT = -7,           // Waitpid timed out
    INJ_ERR_GADGET_NOT_FOUND = -8,  // libc scan failed
    INJ_ERR_INVALID_PID = -9        // Invalid input PID
} InjectorStatus;

// Ptrace Polyfills for older NDKs
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP (1 << 7)
#endif

// Memory Alignment Helper
extern long g_page_size;
#define PAGE_ALIGN(x) (((x) + g_page_size - 1) & ~(g_page_size - 1))

// Signal & Stop Check Helpers
#define PTRACE_SYSCALL_FLAG 0x80
#define STOPPED_WITH_EVENT(status, event) \
    (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && ((status) >> 16) == (event))

// ============================================================================
// ARCHITECTURE SPECIFICS (AArch64 / ARM)
// ============================================================================

#if defined(__aarch64__)
    typedef struct user_pt_regs pt_regs_t;
    #define REG_PC(regs)      ((regs)->pc)
    #define REG_SP(regs)      ((regs)->sp) 
    #define REG_LR(regs)      ((regs)->regs[30])
    #define REG_SYSCALL(regs) ((regs)->regs[8])
    #define REG_RES(regs)     ((regs)->regs[0])
    #define REG_ARG_N(regs, n) ((regs)->regs[n])
    
    #define GADGET_OPCODE     0xd4000001 // svc #0
    #define SCAN_STEP         4

    // Syscall Numbers
    #define SYS_CLONE_FORK 220
    #define SYS_EXIT       93
    #define SYS_MMAP       222
    #define SYS_WRITE      64
    #define SYS_MPROTECT   226 

#elif defined(__arm__)
    typedef struct pt_regs pt_regs_t;
    #define REG_PC(regs)      ((regs)->uregs[15])
    #define REG_SP(regs)      ((regs)->uregs[13]) 
    #define REG_LR(regs)      ((regs)->uregs[14])
    #define REG_CPSR(regs)    ((regs)->uregs[16])
    #define REG_SYSCALL(regs) ((regs)->uregs[7])
    #define REG_RES(regs)     ((regs)->uregs[0])
    #define REG_ARG_N(regs, n) ((regs)->uregs[n])

    #define GADGET_OPCODE_ARM   0xef000000 
    #define GADGET_OPCODE_THUMB 0xdf00     
    #define SCAN_STEP           2          

    // Syscall Numbers
    #define SYS_CLONE_FORK 120 
    #define SYS_EXIT       1
    #define SYS_MMAP       192
    #define SYS_WRITE      4
    #define SYS_MPROTECT   125
    #define SYS_ARM_CACHEFLUSH 0xf0002
#else
    #error "Architecture not supported. Only ARM and AArch64."
#endif

// ============================================================================
// GLOBAL STATE DECLARATIONS
// ============================================================================

/**
 * @brief Wrapper to simplify ptrace register operations.
 */
typedef struct {
    struct iovec iov;
    pt_regs_t regs;
} target_regs_wrapper;

// Process chain PIDs
extern int g_target_pid;
extern int g_child_pid;
extern int g_grandchild_pid;

// Shellcode configuration
extern bool g_is_thumb_shellcode;
extern unsigned char g_mock_shellcode[];

#endif // INJECTOR_H
