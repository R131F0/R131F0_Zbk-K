/**
 * @file main.c
 * @brief Entry point and orchestration of the injection pipeline.
 */

#include "injector.h"
#include "gadget.h"
#include "phases.h"

// ----------------------------------------------------------------------------
// GLOBAL STATE INITIALIZATION
// ----------------------------------------------------------------------------
int g_target_pid = -1;
int g_child_pid = -1;
int g_grandchild_pid = -1;
bool g_is_thumb_shellcode = false;
long g_page_size = 4096;

int main(int argc, char **argv) {
    InjectorStatus status = INJ_SUCCESS;
    int parent_pid = 0;
    
    LOGD("=== Android Zygote Injector (Gadget Variant) ===");

    // Initialize System Page Size
    long sys_pagesize = sysconf(_SC_PAGESIZE);
    if (sys_pagesize > 0) g_page_size = sys_pagesize;
    
    // Root check (Required for ptrace on Android)
    if (geteuid() != 0) {
        LOGE("ERROR: Tool requires Root.");
        return INJ_ERR_PERMISSION;
    }

    // Argument / Config Parsing
    if (argc > 1) {
        parent_pid = atoi(argv[1]);
    } else {
        FILE *fp = fopen("/data/local/tmp/config.txt", "r");
        if (fp) {
            char line[64];
            if (fgets(line, sizeof(line), fp)) parent_pid = atoi(line);
            fclose(fp);
        }
    }
    
    if (parent_pid <= 0) {
        LOGE("Usage: ./injector [pid]");
        return INJ_ERR_INVALID_PID;
    }
    g_target_pid = parent_pid;

    // ------------------------------------------------------------------------
    // INJECTION PIPELINE
    // ------------------------------------------------------------------------

    // Step 0: Pre-scan for gadget (Failure here avoids touching Zygote)
    if (injector_init_gadget(g_target_pid) != INJ_SUCCESS) {
        LOGE("ABORT: Gadget scan failed.");
        return INJ_ERR_GADGET_NOT_FOUND;
    }

    // Step 1: Attach to Zygote
    if ((status = phase_1_seize_zygote(g_target_pid)) != INJ_SUCCESS) goto cleanup;

    // Step 2: Fork the Middleman
    if ((status = phase_2_create_middleman(g_target_pid)) != INJ_SUCCESS) goto cleanup;
    
    // Step 3: Detach Zygote (Critical Safety Step)
    if ((status = phase_3_detach_zygote(g_target_pid)) != INJ_SUCCESS) { 
        LOGE("CRITICAL ABORT: Detach failed."); 
        goto cleanup; 
    }
    
    // Step 4: Fork the Payload Carrier
    if ((status = phase_4_create_payload_carrier(g_child_pid)) != INJ_SUCCESS) goto cleanup;

    // Step 5: Reap Middleman (Zygote cleans it up)
    phase_5_cleanup_middleman(g_child_pid);

    // Step 6: Inject and Execute in Carrier
    if ((status = phase_6_inject_payload(g_grandchild_pid)) != INJ_SUCCESS) goto cleanup;

    LOGD("SUCCESS: Payload injected.");

cleanup:
    if (status != INJ_SUCCESS) {
        LOGE("Injection failed with error code: %d", status);
    }

    // Final Safety Net: Detach any lingering traced processes
    if (g_target_pid > 0) ptrace(PTRACE_DETACH, g_target_pid, 0, 0);
    if (g_child_pid > 0) ptrace(PTRACE_DETACH, g_child_pid, 0, 0);
    if (g_grandchild_pid > 0) ptrace(PTRACE_DETACH, g_grandchild_pid, 0, 0);

    return (int)status;
}
