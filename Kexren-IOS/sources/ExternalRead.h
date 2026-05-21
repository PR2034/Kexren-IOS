//
// ExternalRead.h — Layer 1+2: task_for_pid credential patch + mach_vm_read wrapper.
//
// After DarkSword gives us kernel R/W, this module:
//   1. Finds CODM's proc in the kernel process list
//   2. Patches our task's IPC space so task_for_pid(codm_pid) succeeds
//   3. Provides vm_read wrappers to read CODM's address space
//

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif

// Set a log callback so ext_attach logs appear on the UI.
// Pass the same callback you give to ds_set_log_callback().
void ext_set_log_callback(void (*cb)(const char *));

// Initialize: find CODM, patch creds, obtain task port.
// Returns 0 on success, negative on failure.
// Must be called AFTER ds_run() succeeds.
int ext_attach(void);

// Is CODM attached and readable?
bool ext_is_attached(void);

// Get CODM's task port (only valid after ext_attach).
mach_port_t ext_codm_task(void);

// Get CODM's PID.
pid_t ext_codm_pid(void);

// Get CODM's base address (dyld slide + image base).
uint64_t ext_codm_base(void);

// Read memory from CODM's address space.
bool ext_read(uint64_t address, void *buffer, size_t size);

// Convenience typed reads.
uint64_t ext_read64(uint64_t address);
uint32_t ext_read32(uint64_t address);
float    ext_readf(uint64_t address);

// Read a pointer and strip PAC bits.
uint64_t ext_readptr(uint64_t address);

#ifdef __cplusplus
}
#endif
