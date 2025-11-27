/**
 * @file engine.c
 * @brief Implementation of the Injection Engine.
 *
 * This module manages the delicate state machine required to inject
 * syscalls via gadget redirection without crashing the target.
 */

#include "engine.h"
#include "utils.h"
#include "gadget.h"

// ----------------------------------------------------------------------------
// PUBLIC API
// ----------------------------------------------------------------------------

InjectorStatus wait_and_handle_events(int pid, int *out_status) {
    int status;
    while (true) {
        InjectorStatus wait_res = waitpid_with_timeout(pid, &status, OPERATION_TIMEOUT_MS);
        if (wait_res != INJ_SUCCESS) return wait_res;

        // --- Fork/Clone Event Handling ---
        // We trap these to capture PIDs of the Middleman and Grandchild
        if (STOPPED_WITH_EVENT(status, PTRACE_EVENT_FORK) || 
            STOPPED_WITH_EVENT(status, PTRACE_EVENT_CLONE)) {
            
            unsigned long new_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) != -1) {
                LOGD("Trapped Fork/Clone. New PID: %lu", new_pid);
                if (g_child_pid == -1) g_child_pid = (int)new_pid;
                else if (g_grandchild_pid == -1) g_grandchild_pid = (int)new_pid;
            }
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }

        // --- Seccomp Event Handling ---
        // Critical for stability. We neutralize blocked syscalls to prevent crashes.
        if (STOPPED_WITH_EVENT(status, PTRACE_EVENT_SECCOMP)) {
            LOGV("PTRACE_EVENT_SECCOMP triggered. Neutralizing syscall.");
            target_regs_wrapper wrapper;
            init_regs_wrapper(&wrapper);
            
            // Set syscall number to -1 so kernel returns ENOSYS instead of SIGKILL
            if (get_regs(pid, &wrapper) == INJ_SUCCESS) {
                REG_SYSCALL(&wrapper.regs) = -1; 
                set_regs(pid, &wrapper);
            }
            
            // CRITICAL FIX: Use PTRACE_SYSCALL instead of PTRACE_CONT.
            // This ensures we trap at the upcoming neutralized "Entry Stop",
            // keeping the remote_syscall state machine synchronized.
            ptrace(PTRACE_SYSCALL, pid, 0, 0); 
            continue; 
        }

        // --- Process Exit/Death ---
        if (WIFEXITED(status)) {
            LOGV("Process exited normally with status %d", WEXITSTATUS(status));
            *out_status = status;
            return INJ_SUCCESS;
        }
        if (WIFSIGNALED(status)) {
            LOGV("Process killed by signal %d", WTERMSIG(status));
            *out_status = status;
            return INJ_SUCCESS;
        }

        // --- Standard Stop ---
        *out_status = status;
        return INJ_SUCCESS;
    }
}

InjectorStatus wait_for_initial_stop(int pid) {
    int status;
    InjectorStatus res = waitpid_with_timeout(pid, &status, OPERATION_TIMEOUT_MS * 2);
    if (res != INJ_SUCCESS) return res;
    
    if (WIFSTOPPED(status)) return INJ_SUCCESS;
    return INJ_ERR_GENERIC;
}

InjectorStatus remote_syscall(int pid, long *out_result, long sysno, ...) {
    if (injector_init_gadget(pid) != INJ_SUCCESS) {
        LOGE("Cannot execute remote syscall: Gadget not initialized");
        return INJ_ERR_GADGET_NOT_FOUND;
    }

    LOGD("Preparing Remote Syscall #%ld for PID %d", sysno, pid);

    target_regs_wrapper regs_orig, regs_modified;
    init_regs_wrapper(&regs_orig);
    init_regs_wrapper(&regs_modified);
    
    bool process_died = false;
    InjectorStatus status = INJ_SUCCESS;
    *out_result = -ENOSYS; 

    // 1. Backup Registers
    if ((status = get_regs(pid, &regs_orig)) != INJ_SUCCESS) return status;

    memcpy(&regs_modified, &regs_orig, sizeof(target_regs_wrapper));

    // 2. Prepare Arguments
    va_list args;
    va_start(args, sysno);
    for (int i = 0; i < 6; i++) {
        long arg_val = va_arg(args, long);
        REG_ARG_N(&regs_modified.regs, i) = arg_val;
    }
    va_end(args);

    // 3. Setup Redirection
    REG_SYSCALL(&regs_modified.regs) = sysno;

    // Stack Alignment (16-byte)
    // Essential for stability if signal handlers run or kernel checks alignment.
    unsigned long current_sp = REG_SP(&regs_modified.regs);
    REG_SP(&regs_modified.regs) = current_sp & ~0xF;

    #if defined(__arm__)
    if (g_is_thumb_gadget) {
        REG_PC(&regs_modified.regs) = g_cached_gadget | 1;
        REG_CPSR(&regs_modified.regs) |= (1 << 5);
    } else {
        REG_PC(&regs_modified.regs) = g_cached_gadget;
        REG_CPSR(&regs_modified.regs) &= ~(1 << 5);
    }
    #else
    REG_PC(&regs_modified.regs) = g_cached_gadget;
    #endif

    if ((status = set_regs(pid, &regs_modified)) != INJ_SUCCESS) goto cleanup;

    // 4. Run to Syscall Entry
    int sig_inject = 0;
    while(true) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, sig_inject) == -1) {
             status = INJ_ERR_GENERIC; goto cleanup; 
        }
        
        int wait_stat;
        status = wait_and_handle_events(pid, &wait_stat);
        if (status != INJ_SUCCESS) goto cleanup;
        
        if (WIFEXITED(wait_stat) || WIFSIGNALED(wait_stat)) {
            if (sysno == SYS_EXIT) { process_died = true; *out_result = 0; status = INJ_SUCCESS; goto cleanup; }
            LOGE("Process died waiting for syscall entry");
            status = INJ_ERR_GENERIC;
            goto cleanup;
        }
        if (!WIFSTOPPED(wait_stat)) { status = INJ_ERR_GENERIC; goto cleanup; }
        // Check for specific syscall trap
        if ((WSTOPSIG(wait_stat) & ~PTRACE_SYSCALL_FLAG) == SIGTRAP) break; 
        
        sig_inject = WSTOPSIG(wait_stat);
        if (sig_inject == SIGTRAP) sig_inject = 0; 
    }

    // 5. Run to Syscall Exit
    sig_inject = 0;
    while(true) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, sig_inject) == -1) {
            status = INJ_ERR_GENERIC; goto cleanup;
        }

        int wait_stat;
        status = wait_and_handle_events(pid, &wait_stat);
        if (status != INJ_SUCCESS) goto cleanup;
        
        if (WIFEXITED(wait_stat) || WIFSIGNALED(wait_stat)) {
            if (sysno == SYS_EXIT) { process_died = true; *out_result = 0; status = INJ_SUCCESS; goto cleanup; }
            LOGE("Process died waiting for syscall exit");
            status = INJ_ERR_GENERIC;
            goto cleanup;
        }
        if (!WIFSTOPPED(wait_stat)) { status = INJ_ERR_GENERIC; goto cleanup; }
        // Check for specific syscall trap
        if ((WSTOPSIG(wait_stat) & ~PTRACE_SYSCALL_FLAG) == SIGTRAP) break; 
        
        sig_inject = WSTOPSIG(wait_stat);
        if (sig_inject == SIGTRAP) sig_inject = 0;
    }

    // 6. Retrieve Result
    if ((status = get_regs(pid, &regs_modified)) == INJ_SUCCESS) {
        *out_result = REG_RES(&regs_modified.regs);
        LOGD("Syscall #%ld returned: %lx", sysno, *out_result);
    }

cleanup:
    // Atomic Restore: Ensure we don't leave the process with a corrupted PC
    if (!process_died) set_regs(pid, &regs_orig);
    return status;
}
