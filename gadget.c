/**
 * @file gadget.c
 * @brief Implementation of memory scanning logic.
 */

#include "gadget.h"
#include "utils.h"

// Global Gadget Cache
unsigned long g_cached_gadget = 0;
bool g_is_thumb_gadget = false;

// ----------------------------------------------------------------------------
// INTERNAL HELPER: Scan a memory block for gadget opcodes
// ----------------------------------------------------------------------------
static unsigned long scan_region_for_gadget(int pid, unsigned long start, unsigned long end) {
    unsigned char buf[4096] __attribute__((aligned(4))); 
    unsigned long curr = start;
    
    while (curr < end) {
        // Align reads to page boundaries
        size_t bytes_in_page = g_page_size - (curr % g_page_size);
        size_t remaining_in_region = end - curr;
        size_t to_read = (bytes_in_page < remaining_in_region) ? bytes_in_page : remaining_in_region;
        
        if (to_read > sizeof(buf)) to_read = sizeof(buf);

        // Safely read. If XOM (Execute-Only Memory), this fails gracefully.
        if (read_remote_chunk(pid, curr, buf, to_read) != INJ_SUCCESS) {
            curr += bytes_in_page; // Skip unreadable page
            continue;
        }

        if (to_read < SCAN_STEP) {
            curr += to_read;
            continue;
        }

        // Calculate alignment padding
        size_t padding = (SCAN_STEP - (curr % SCAN_STEP)) % SCAN_STEP;

        for (size_t i = padding; i <= to_read - SCAN_STEP; i += SCAN_STEP) { 
            unsigned long addr = curr + i;
            bool can_read_4 = (i + 4 <= to_read);

            uint32_t val32 = 0;
            uint16_t val16 = 0;
            if (can_read_4) memcpy(&val32, buf + i, sizeof(val32));
            memcpy(&val16, buf + i, sizeof(val16));

#if defined(__aarch64__)
            // AArch64: svc #0 is 0xd4000001
            if (can_read_4 && val32 == GADGET_OPCODE) return addr;
#elif defined(__arm__)
            // ARM: Thumb (svc 0) vs ARM (svc 0)
            if (val16 == GADGET_OPCODE_THUMB) {
                g_is_thumb_gadget = true;
                return addr;
            }
            if (can_read_4 && (addr % 4 == 0) && val32 == GADGET_OPCODE_ARM) {
                g_is_thumb_gadget = false;
                return addr;
            }
#endif
        }
        curr += to_read;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// INTERNAL HELPER: Parse /proc/maps to find libc or vdso
// ----------------------------------------------------------------------------
static unsigned long find_syscall_gadget_internal(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    unsigned long addr_start, addr_end;
    char perms[5];
    char libpath[256] = {0}; 
    unsigned long gadget = 0;
    unsigned long fallback_vdso = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &addr_start, &addr_end, perms, libpath) < 4) continue;

        // Must be executable
        if (strstr(perms, "x")) {
            if (strstr(libpath, "libc.so")) {
                gadget = scan_region_for_gadget(pid, addr_start, addr_end);
                if (gadget) break;
            }
            // VDSO fallback for systems where libc is XOM or obscure
            else if (strstr(libpath, "[vdso]") && fallback_vdso == 0) {
                fallback_vdso = scan_region_for_gadget(pid, addr_start, addr_end);
            }
        }
    }
    fclose(fp);
    return (gadget != 0) ? gadget : fallback_vdso;
}

// ----------------------------------------------------------------------------
// PUBLIC API
// ----------------------------------------------------------------------------
InjectorStatus injector_init_gadget(int pid) {
    if (g_cached_gadget != 0) return INJ_SUCCESS;
    
    unsigned long gadget = find_syscall_gadget_internal(pid);
    if (gadget) {
        g_cached_gadget = gadget;
        return INJ_SUCCESS;
    }
    return INJ_ERR_GADGET_NOT_FOUND;
}
