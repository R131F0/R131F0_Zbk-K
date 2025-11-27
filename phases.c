/**
 * @file phases.c
 * @brief Implementation of the Grandchild Injection strategy steps.
 */

#include "phases.h"
#include "engine.h"
#include "utils.h"

// ----------------------------------------------------------------------------
// GLOBAL SHELLCODE DEFINITIONS
// ----------------------------------------------------------------------------
#if defined(__aarch64__)
unsigned char g_mock_shellcode[] = {
    0x00, 0x00, 0x80, 0xD2, // mov x0, #0
    0xA8, 0x0B, 0x80, 0xD2, // mov x8, #93 (exit)
    0x01, 0x00, 0x00, 0xD4  // svc #0
};
#elif defined(__arm__)
unsigned char g_mock_shellcode[] = {
    0x00, 0x00, 0xA0, 0xE3, // mov r0, #0
    0x01, 0x70, 0xA0, 0xE3, // mov r7, #1 (exit)
    0x00, 0x00, 0x00, 0xEF  // svc 0
};
#endif

// ----------------------------------------------------------------------------
// INTERNAL HELPER: Explicit Instruction Cache Flush
// ----------------------------------------------------------------------------
static InjectorStatus remote_icache_flush(int pid, unsigned long addr, size_t len) {
#if defined(__arm__)
    long res;
    // ARM32 requires explicit cache flushing after writing code.
    InjectorStatus status = remote_syscall(pid, &res, SYS_ARM_CACHEFLUSH, addr, addr + len, 0, 0, 0);
    if (status != INJ_SUCCESS || is_remote_error(res)) return INJ_ERR_SYSCALL_REDIRECT;
#endif
    // AArch64 usually handles icache flush via mprotect/kernel logic, 
    // but explicit flushing is safer if available. For GKI, it's often implicit.
    return INJ_SUCCESS;
}

// ----------------------------------------------------------------------------
// PUBLIC API
// ----------------------------------------------------------------------------

InjectorStatus phase_1_seize_zygote(int pid) {
    LOGD("[1/6] Seizing Zygote (PID %d)...", pid);
    
    // Use PTRACE_SEIZE to attach without stopping immediately. 
    // This is safer for system processes than PTRACE_ATTACH.
    if (ptrace(PTRACE_SEIZE, pid, 0, 
        PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | 
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP) == -1) {
        PLOGE("PTRACE_SEIZE failed");
        return INJ_ERR_ATTACH;
    }
    
    // Interrupt to gain control at a safe point
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        PLOGE("PTRACE_INTERRUPT failed");
        return INJ_ERR_GENERIC;
    }
    
    int wait_status;
    return wait_and_handle_events(pid, &wait_status);
}

InjectorStatus phase_2_create_middleman(int parent_pid) {
    LOGD("[2/6] Creating Middleman...");
    long res;
    InjectorStatus status = remote_syscall(parent_pid, &res, SYS_CLONE_FORK, SIGCHLD, 0, 0, 0, 0);
    if (status != INJ_SUCCESS) return status;
    
    if (res < 0 || g_child_pid <= 0) {
        LOGE("Failed to clone Middleman. Syscall res: %ld", res);
        return INJ_ERR_SYSCALL_REDIRECT;
    }

    if (wait_for_initial_stop(g_child_pid) != INJ_SUCCESS) {
        LOGE("Middleman created but failed to stop.");
        return INJ_ERR_TIMEOUT;
    }
    
    LOGD("Middleman Created (PID: %d)", g_child_pid);
    return INJ_SUCCESS;
}

InjectorStatus phase_3_detach_zygote(int pid) {
    LOGD("[3/6] Detaching Zygote...");
    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
        PLOGE("PTRACE_DETACH failed");
        return INJ_ERR_DETACH;
    }
    g_target_pid = -1; // Mark as detached
    return INJ_SUCCESS;
}

InjectorStatus phase_4_create_payload_carrier(int middleman_pid) {
    LOGD("[4/6] Creating Payload Carrier...");
    
    // Propagate ptrace options so Middleman traces Grandchild
    if (ptrace(PTRACE_SETOPTIONS, middleman_pid, 0, 
        PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP) == -1) {
        PLOGE("Failed to set options on Middleman");
        return INJ_ERR_GENERIC;
    }

    long res;
    InjectorStatus status = remote_syscall(middleman_pid, &res, SYS_CLONE_FORK, SIGCHLD, 0, 0, 0, 0);
    if (status != INJ_SUCCESS) return status;

    if (res < 0 || g_grandchild_pid <= 0) {
        LOGE("Failed to clone Payload Carrier. Syscall res: %ld", res);
        return INJ_ERR_SYSCALL_REDIRECT;
    }

    if (wait_for_initial_stop(g_grandchild_pid) != INJ_SUCCESS) {
        LOGE("Payload Carrier failed to stop.");
        return INJ_ERR_TIMEOUT;
    }
    
    LOGD("Payload Carrier Created (PID: %d)", g_grandchild_pid);
    return INJ_SUCCESS;
}

void phase_5_cleanup_middleman(int middleman_pid) {
    LOGD("[5/6] Cleaning up Middleman...");
    long res;
    // Exit the middleman. The original Zygote will reap it (SIGCHLD).
    remote_syscall(middleman_pid, &res, SYS_EXIT, 0, 0, 0, 0, 0);
    ptrace(PTRACE_DETACH, middleman_pid, 0, 0);
    g_child_pid = -1; 
}

InjectorStatus phase_6_inject_payload(int target_pid) {
    LOGD("[6/6] Injecting Shellcode into Carrier (PID %d)...", target_pid);
    ptrace(PTRACE_SETOPTIONS, target_pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP);
    
    // 1. Map RW Memory (Anonymous)
    size_t map_size = PAGE_ALIGN(sizeof(g_mock_shellcode));
    long map_addr;
    InjectorStatus status = remote_syscall(target_pid, &map_addr, SYS_MMAP, 0, map_size, 
                                 PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    
    if (status != INJ_SUCCESS || is_remote_error(map_addr) || map_addr == 0) {
        LOGE("Remote mmap failed: %ld", map_addr);
        return INJ_ERR_MEMORY_RW;
    }
    LOGD("Remote Memory Allocated: %lx", map_addr);

    // 2. Write Shellcode
    if (write_remote_mem(target_pid, map_addr, g_mock_shellcode, sizeof(g_mock_shellcode)) != INJ_SUCCESS) {
        return INJ_ERR_MEMORY_RW;
    }
    remote_icache_flush(target_pid, map_addr, sizeof(g_mock_shellcode));

    // 3. Protect as RX (Read-Execute)
    // IMPORTANT: W^X compliance (Write XOR Execute)
    long prot_res;
    status = remote_syscall(target_pid, &prot_res, SYS_MPROTECT, map_addr, map_size, PROT_READ|PROT_EXEC, 0, 0, 0);
    if (status != INJ_SUCCESS || is_remote_error(prot_res)) {
        LOGE("Remote mprotect failed");
        return INJ_ERR_MEMORY_RW;
    }

    // 4. Set PC to Payload
    target_regs_wrapper regs;
    init_regs_wrapper(&regs);
    if (get_regs(target_pid, &regs) != INJ_SUCCESS) return INJ_ERR_GENERIC;

    REG_PC(&regs.regs) = map_addr;

    #if defined(__arm__)
    if (g_is_thumb_shellcode) REG_CPSR(&regs.regs) |= 0x20; // Set Thumb bit
    else REG_CPSR(&regs.regs) &= ~0x20;
    #endif

    if (set_regs(target_pid, &regs) != INJ_SUCCESS) return INJ_ERR_GENERIC;

    // 5. Final Detach
    if (ptrace(PTRACE_DETACH, target_pid, 0, 0) == -1) {
        PLOGE("Final Detach failed");
        return INJ_ERR_DETACH;
    }
    g_grandchild_pid = -1; 
    return INJ_SUCCESS;
}
