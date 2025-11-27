/**
 * @file utils.c
 * @brief Implementation of low-level utilities.
 */

#include "utils.h"

void init_regs_wrapper(target_regs_wrapper *wrapper) {
    memset(wrapper, 0, sizeof(target_regs_wrapper));
    wrapper->iov.iov_base = &wrapper->regs;
    wrapper->iov.iov_len = sizeof(wrapper->regs);
}

InjectorStatus get_regs(int pid, target_regs_wrapper *wrapper) {
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &wrapper->iov) == -1) {
        PLOGE("ptrace(PTRACE_GETREGSET) failed");
        return INJ_ERR_GENERIC;
    }
    return INJ_SUCCESS;
}

InjectorStatus set_regs(int pid, target_regs_wrapper *wrapper) {
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &wrapper->iov) == -1) {
        PLOGE("ptrace(PTRACE_SETREGSET) failed");
        return INJ_ERR_GENERIC;
    }
    return INJ_SUCCESS;
}

bool is_remote_error(long res) {
    // Linux errno values are negative, within the range [-4096, -1]
    return (unsigned long)res > (unsigned long)-4096UL;
}

InjectorStatus read_remote_chunk(int pid, unsigned long addr, void *buf, size_t len) {
    struct iovec local = {buf, len};
    struct iovec remote = {(void *)addr, len};
    ssize_t res = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    
    if (res != (ssize_t)len) {
        // Verbose log only (expected behavior during gadget scanning holes)
        LOGV("read_remote_chunk partial read at %lx: %s", addr, strerror(errno));
        return INJ_ERR_MEMORY_RW;
    }
    return INJ_SUCCESS;
}

InjectorStatus write_remote_mem(int pid, unsigned long addr, void *buf, size_t len) {
    LOGD("Writing %zu bytes to PID %d at %lx", len, pid, addr);
    size_t total_written = 0;
    while (total_written < len) {
        struct iovec local = {(char *)buf + total_written, len - total_written};
        struct iovec remote = {(void *)(addr + total_written), len - total_written};
        
        ssize_t res = process_vm_writev(pid, &local, 1, &remote, 1, 0);
        if (res == -1) {
            if (errno == EINTR) continue;
            PLOGE("process_vm_writev failed");
            return INJ_ERR_MEMORY_RW;
        }
        if (res == 0) {
            LOGE("process_vm_writev stalled (0 bytes)");
            return INJ_ERR_MEMORY_RW;
        }
        total_written += res;
    }
    return INJ_SUCCESS;
}

InjectorStatus waitpid_with_timeout(int pid, int *out_status, int timeout_ms) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) return INJ_ERR_GENERIC;

    while (true) {
        // Polling wait for simple timeout implementation
        int res = waitpid(pid, out_status, __WALL | WNOHANG);
        if (res > 0) return INJ_SUCCESS; 
        if (res == -1) {
            if (errno == EINTR) continue;
            PLOGE("waitpid failed");
            return INJ_ERR_GENERIC;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) return INJ_ERR_GENERIC;
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + 
                          (now.tv_nsec - start.tv_nsec) / 1000000;
        
        if (elapsed_ms >= timeout_ms) {
            LOGE("TIMEOUT: Process %d unresponsive for %dms", pid, timeout_ms);
            errno = ETIMEDOUT;
            return INJ_ERR_TIMEOUT;
        }
        usleep(2000); // 2ms polling interval
    }
}
