/**
 * @file gadget.h
 * @brief API for locating the "syscall gadget" in remote processes.
 */

#ifndef GADGET_H
#define GADGET_H

#include "injector.h"

// Public API
InjectorStatus injector_init_gadget(int pid);

// Shared state required by Engine to perform redirection
extern unsigned long g_cached_gadget;
extern bool g_is_thumb_gadget;

#endif // GADGET_H
