/**
 * @file phases.h
 * @brief High-level injection phases.
 */

#ifndef PHASES_H
#define PHASES_H

#include "injector.h"

// Public API
InjectorStatus phase_1_seize_zygote(int pid);
InjectorStatus phase_2_create_middleman(int parent_pid);
InjectorStatus phase_3_detach_zygote(int pid);
InjectorStatus phase_4_create_payload_carrier(int middleman_pid);
void phase_5_cleanup_middleman(int middleman_pid);
InjectorStatus phase_6_inject_payload(int target_pid);

#endif // PHASES_H
