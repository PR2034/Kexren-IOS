//
// ExternalRead.m — Cross-process memory access via kernel R/W + page table walk.
//
// After DarkSword gives us kernel R/W, this module:
//   1. Finds CODM's proc in the kernel process list
//   2. Resolves CODM's pmap (page tables) via proc → task → vm_map → pmap
//   3. Walks ARM64 page tables to translate CODM user VAs to physical addresses
//   4. Reads physical memory through the kernel physmap using ds_kread64
//
// This bypasses mach_vm_read_overwrite entirely — that approach hangs on
// iOS 17.6.1 A14 with fabricated task ports.
//

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#import "ExternalRead.h"
#import "../kexploit/darksword.h"
#import "../kexploit/offsets.h"
#import "../kexploit/utils.h"
#import "../kexploit/pe/sbx.h"
#include <mach-o/loader.h>

extern uint64_t kernel_base;

static pid_t       g_codm_pid  = 0;
static uint64_t    g_codm_base = 0;
static bool        g_attached  = false;

// Kernel R/W state for cross-process reads.
static uint64_t    g_codm_task_kaddr = 0;  // CODM's kernel task address
static uint64_t    g_codm_pmap       = 0;  // CODM's pmap kernel address
static uint64_t    g_codm_ttep       = 0;  // CODM's page table base (physical addr)
static uint64_t    g_physmap_offset   = 0;  // gVirtBase - gPhysBase

// Simple 1-entry TLB cache to avoid redundant page walks for same-page reads.
static uint64_t    g_cached_vpage    = ~0ULL;
static uint64_t    g_cached_ppage    = 0;

// Match CODM process name.
// "cod" requires EXACT match (otherwise hits "PasscodeSettingsSubscriber" etc.)
// Longer strings use substring match.
static bool match_codm_name(const char *name) {
    if (strcasecmp(name, "cod") == 0) return true;          // exact
    if (strcasestr(name, "codm") != NULL) return true;       // substring
    if (strcasestr(name, "shooter") != NULL) return true;    // substring
    if (strcasestr(name, "callofduty") != NULL) return true; // substring
    return false;
}

static void (*g_ext_log_cb)(const char *) = NULL;
static FILE *g_log_file = NULL;
static NSString *g_log_path = nil;

void ext_set_log_callback(void (*cb)(const char *)) {
    g_ext_log_cb = cb;
}

static void open_log_file(void) {
    if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
    NSArray *paths = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docs = [paths firstObject];
    if (!docs) docs = NSHomeDirectory();
    g_log_path = [docs stringByAppendingPathComponent:@"acluna_log.txt"];
    g_log_file = fopen(g_log_path.UTF8String, "w");
    if (g_log_file) {
        fprintf(g_log_file, "=== ACLuna-External log ===\n");
        fprintf(g_log_file, "path: %s\n", g_log_path.UTF8String);
        fflush(g_log_file);
    }
}

static void close_log_file(void) {
    if (g_log_file) { fclose(g_log_file); g_log_file = NULL; }
}

static void pe_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void pe_log(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("(ext) %s\n", buf);
    if (g_ext_log_cb) g_ext_log_cb(buf);
    if (g_log_file) {
        fprintf(g_log_file, "%s\n", buf);
        fflush(g_log_file);
    }
}

// ============================================================================
//  Process list walking — find CODM by name
// ============================================================================

static void read_proc_name(uint64_t proc, char *out, size_t out_len) {
    memset(out, 0, out_len);
    if (!proc) return;
    uint32_t name_off = off_proc_p_name;
    if (!name_off) name_off = 0x57d;
    uint64_t aligned = proc + (name_off & ~7ULL);
    uint64_t adjust  = name_off & 7;
    char tmp[40] = {0};
    ds_kreadbuf(aligned, tmp, 40);
    size_t copy_len = (out_len - 1 < 32) ? out_len - 1 : 32;
    memcpy(out, tmp + adjust, copy_len);
    out[copy_len] = '\0';
}

static uint64_t find_codm_proc(pid_t *out_pid) {
    uint64_t self_proc = proc_self();
    if (!self_proc) {
        pe_log("proc_self() failed");
        return 0;
    }
    pe_log("proc_self: 0x%llx", self_proc);

    uint32_t next_off = off_proc_p_list_le_next;
    if (!next_off) next_off = 0x0;
    uint32_t pid_off = off_proc_p_pid;
    if (!pid_off) pid_off = 0x60;

    // Walk forward.
    uint64_t proc = self_proc;
    int iter = 0;
    while (proc && iter < 2000) {
        char name[64] = {0};
        read_proc_name(proc, name, sizeof(name));
        uint32_t pid = ds_kread32(proc + pid_off);

        if (name[0] != '\0' && pid > 1) {
            if (match_codm_name(name)) {
                pe_log("found '%s' pid=%d kaddr=0x%llx", name, pid, proc);
                *out_pid = (pid_t)pid;
                return proc;
            }
        }

        uint64_t next = ds_kread64(proc + next_off);
        if (!next || next == proc) break;
        if ((next & 0xffff000000000000ULL) != 0xffff000000000000ULL) break;
        proc = next;
        iter++;
    }

    // Walk backward.
    uint32_t prev_off = off_proc_p_list_le_prev ? off_proc_p_list_le_prev : 0x8;
    proc = ds_kread64(self_proc + prev_off);
    iter = 0;
    while (proc && iter < 2000) {
        if ((proc & 0xffff000000000000ULL) != 0xffff000000000000ULL) break;

        char name[64] = {0};
        read_proc_name(proc, name, sizeof(name));
        uint32_t pid = ds_kread32(proc + pid_off);

        if (name[0] != '\0' && pid > 1) {
            if (match_codm_name(name)) {
                pe_log("found '%s' pid=%d kaddr=0x%llx", name, pid, proc);
                *out_pid = (pid_t)pid;
                return proc;
            }
        }

        uint64_t prev = ds_kread64(proc + prev_off);
        if (!prev || prev == proc) break;
        proc = prev;
        iter++;
    }

    // Not found — dump first 20 procs for debug.
    pe_log("CODM not found. Process dump:");
    proc = self_proc;
    iter = 0;
    while (proc && iter < 20) {
        char name[64] = {0};
        read_proc_name(proc, name, sizeof(name));
        uint32_t pid = ds_kread32(proc + pid_off);
        pe_log("  [%d] pid=%d name='%s'", iter, pid, name);
        uint64_t next = ds_kread64(proc + next_off);
        if (!next || next == proc) break;
        if ((next & 0xffff000000000000ULL) != 0xffff000000000000ULL) break;
        proc = next;
        iter++;
    }

    return 0;
}

// ============================================================================
//  PAC-safe task lookup
// ============================================================================

static uint64_t safe_taskbyproc(uint64_t procaddr) {
    if (!ds_isvalid(procaddr)) {
        pe_log("safe_taskbyproc: invalid proc 0x%llx", procaddr);
        return 0;
    }
    uint64_t p_proc_ro = ds_kreadptr(procaddr + off_proc_p_proc_ro);
    pe_log("  proc_ro: 0x%llx (proc+0x%x)", p_proc_ro, off_proc_p_proc_ro);
    if (!ds_isvalid(p_proc_ro)) {
        pe_log("safe_taskbyproc: proc_ro invalid 0x%llx", p_proc_ro);
        return 0;
    }
    uint64_t pr_task = ds_kreadptr(p_proc_ro + off_proc_ro_pr_task);
    pe_log("  pr_task: 0x%llx (proc_ro+0x%x)", pr_task, off_proc_ro_pr_task);
    if (!ds_isvalid(pr_task)) {
        pe_log("safe_taskbyproc: task invalid 0x%llx", pr_task);
        return 0;
    }
    return pr_task;
}

// ============================================================================
//  ARM64 page table walk — translate user VA → physical address
// ============================================================================

// Convert physical address to kernel VA through the physmap.
static inline uint64_t pa_to_kva(uint64_t pa) {
    return pa + g_physmap_offset;
}

// Page table entry bits (ARM64, 4K granule).
#define PTE_VALID       (1ULL << 0)
#define PTE_TYPE_TABLE  (1ULL << 1)   // at L1/L2: table if set, block if clear
#define PTE_ADDR_MASK   0x0000FFFFFFFFF000ULL  // bits [47:12]

// Walk ARM64 page tables for user VA.
// A14 T0SZ=25 → 39-bit VA → 3-level walk (L1 → L2 → L3), 4K pages.
//   L1 index = VA[38:30]  (covers 1 GB per entry, 512 entries)
//   L2 index = VA[29:21]  (covers 2 MB per entry, 512 entries)
//   L3 index = VA[20:12]  (covers 4 KB per entry, 512 entries)
//   Page offset = VA[11:0]
static uint64_t pmap_walk_va(uint64_t ttep_phys, uint64_t va) {
    uint64_t l1_idx = (va >> 30) & 0x1FF;
    uint64_t l2_idx = (va >> 21) & 0x1FF;
    uint64_t l3_idx = (va >> 12) & 0x1FF;
    uint64_t pg_off = va & 0xFFF;

    // --- L1 ---
    uint64_t l1_kva = pa_to_kva(ttep_phys + l1_idx * 8);
    if (!ds_isvalid(l1_kva)) return 0;
    uint64_t l1_pte = ds_kread64(l1_kva);
    if (!(l1_pte & PTE_VALID)) return 0;

    if (!(l1_pte & PTE_TYPE_TABLE)) {
        // L1 block descriptor (1 GB region).
        return (l1_pte & 0x0000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }

    // --- L2 ---
    uint64_t l2_base = l1_pte & PTE_ADDR_MASK;
    uint64_t l2_kva  = pa_to_kva(l2_base + l2_idx * 8);
    if (!ds_isvalid(l2_kva)) return 0;
    uint64_t l2_pte  = ds_kread64(l2_kva);
    if (!(l2_pte & PTE_VALID)) return 0;

    if (!(l2_pte & PTE_TYPE_TABLE)) {
        // L2 block descriptor (2 MB region).
        return (l2_pte & 0x0000FFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    }

    // --- L3 ---
    uint64_t l3_base = l2_pte & PTE_ADDR_MASK;
    uint64_t l3_kva  = pa_to_kva(l3_base + l3_idx * 8);
    if (!ds_isvalid(l3_kva)) return 0;
    uint64_t l3_pte  = ds_kread64(l3_kva);
    if (!(l3_pte & PTE_VALID)) return 0;

    // L3 page descriptor (4 KB page).
    return (l3_pte & PTE_ADDR_MASK) | pg_off;
}

// Cached page table walk — avoids re-walking for consecutive reads on same page.
static uint64_t cached_pmap_walk(uint64_t va) {
    uint64_t vpage = va & ~0xFFFULL;
    if (vpage == g_cached_vpage && g_cached_ppage != 0) {
        return g_cached_ppage | (va & 0xFFF);
    }
    uint64_t pa = pmap_walk_va(g_codm_ttep, va);
    if (pa) {
        g_cached_vpage = vpage;
        g_cached_ppage = pa & ~0xFFFULL;
    }
    return pa;
}

// ============================================================================
//  Pmap + physmap discovery
// ============================================================================

// Strip PAC bits from a kernel pointer.
// On arm64 (non-arm64e) builds, xpaci is a no-op, so we must do it manually.
// Uses pac_mask (set from t1sz_boot in offsets_init).
static inline uint64_t kptr_strip_pac(uint64_t ptr) {
    if (ptr >> 63) {
        // Kernel pointer (upper half): sign-extend from VA width.
        // pac_mask has the correct bits for the configured t1sz_boot.
        if (pac_mask) {
            ptr |= pac_mask;
        } else {
            // Fallback for T1SZ=25 (39-bit VA): set bits [62:39] to 1.
            ptr |= 0xFFFFFF8000000000ULL;
        }
    }
    return ptr;
}

// Validate a tte/ttep candidate by checking if the L1 table has valid entries.
// A real page table has at least a few valid L1 entries (code, stack, heap).
// A false positive from a random struct will have garbage.
static int count_valid_l1_entries(uint64_t ttep_phys, uint64_t physmap_off) {
    int count = 0;
    for (int i = 0; i < 32 && count == 0; i++) {
        uint64_t l1_pa  = ttep_phys + i * 8;
        uint64_t l1_kva = l1_pa + physmap_off;
        if (!ds_isvalid(l1_kva)) continue;
        uint64_t pte = ds_kread64(l1_kva);
        if (pte & PTE_VALID) count++;
    }
    return count;
}

// Find pmap in vm_map by probing offsets.
// With PPL (A12+, XNU_MONITOR), the pmap struct has many fields BEFORE tte/ttep:
//   cpu_data_entries[], lock_mode, rwlock, pmap_prev, pmap_next, THEN tte, ttep.
// So we scan up to +0xC0 within the pmap candidate.
// We validate each candidate by checking the L1 page table has valid entries.
static uint64_t find_pmap_in_vm_map(uint64_t vm_map_kaddr) {
    pe_log("scanning vm_map 0x%llx for pmap...", vm_map_kaddr);

    // Dump raw vm_map fields for debugging.
    pe_log("vm_map raw dump (+0x28..+0x70):");
    for (uint32_t off = 0x28; off <= 0x70; off += 8) {
        uint64_t raw = ds_kread64(vm_map_kaddr + off);
        uint64_t fixed = kptr_strip_pac(raw);
        pe_log("  +0x%02x: raw=0x%llx fixed=0x%llx v=%d",
               off, raw, fixed, ds_isvalid(fixed));
    }

    // Try each vm_map offset for the pmap pointer.
    for (uint32_t off = 0x28; off <= 0x70; off += 8) {
        uint64_t raw = ds_kread64(vm_map_kaddr + off);

        uint64_t try_ptrs[2] = { raw, kptr_strip_pac(raw) };
        int n_try = (try_ptrs[0] == try_ptrs[1]) ? 1 : 2;

        for (int c = 0; c < n_try; c++) {
            uint64_t maybe_pmap = try_ptrs[c];
            if (!ds_isvalid(maybe_pmap)) continue;

            // Scan deep into pmap struct for tte/ttep pairs.
            // PPL pmap has cpu_data + locks before tte/ttep, so scan up to +0xC0.
            for (uint32_t p = 0; p <= 0xB8; p += 0x08) {
                uint64_t fa_addr = maybe_pmap + p;
                uint64_t fb_addr = maybe_pmap + p + 0x08;
                if (!ds_isvalid(fa_addr) || !ds_isvalid(fb_addr)) continue;

                uint64_t field_a_raw = ds_kread64(fa_addr);
                uint64_t field_b     = ds_kread64(fb_addr);

                uint64_t tte  = kptr_strip_pac(field_a_raw);
                uint64_t ttep = field_b;

                bool tte_ok  = ds_isvalid(tte);
                bool ttep_ok = (ttep > 0x100000000ULL && ttep < 0x10000000000ULL);

                if (tte_ok && ttep_ok) {
                    uint64_t offset = tte - ttep;

                    // VALIDATE: check if L1 page table has real entries.
                    int valid_l1 = count_valid_l1_entries(ttep, offset);
                    pe_log("  candidate vm_map+0x%02x pmap+0x%02x: "
                           "tte=0x%llx ttep=0x%llx L1valid=%d",
                           off, p, tte, ttep, valid_l1);

                    if (valid_l1 > 0) {
                        pe_log("CONFIRMED pmap at vm_map+0x%x = 0x%llx",
                               off, maybe_pmap);
                        pe_log("  tte(+0x%02x)  = 0x%llx (KVA)", p, tte);
                        pe_log("  ttep(+0x%02x) = 0x%llx (phys)", p + 8, ttep);
                        pe_log("  physmap offset = 0x%llx", offset);
                        pe_log("  valid L1 entries = %d", valid_l1);

                        g_physmap_offset = offset;
                        g_codm_ttep      = ttep;
                        return maybe_pmap;
                    }
                }
            }
        }
    }

    pe_log("pmap NOT found after full scan.");
    return 0;
}

// ============================================================================
//  Resolve CODM base address
// ============================================================================

static uint64_t resolve_codm_base_kread(void) {
    struct mach_header_64 header;

    for (uint64_t probe = 0x100000000ULL; probe < 0x108000000ULL; probe += 0x100000) {
        memset(&header, 0, sizeof(header));
        bool ok = true;

        // Read mach_header_64 (32 bytes = 4 x 8-byte reads).
        for (int i = 0; i < (int)sizeof(header) && ok; i += 8) {
            uint64_t pa = cached_pmap_walk(probe + i);
            if (!pa) { ok = false; break; }
            uint64_t kva = pa_to_kva(pa);
            if (!ds_isvalid(kva)) { ok = false; break; }
            uint64_t val = ds_kread64(kva);
            size_t n = ((size_t)(sizeof(header) - i) >= 8) ? 8 : (sizeof(header) - i);
            memcpy((uint8_t *)&header + i, &val, n);
        }

        if (ok && header.magic == MH_MAGIC_64 && header.filetype == MH_EXECUTE) {
            pe_log("CODM base: 0x%llx (cputype=%d)", probe, header.cputype);
            return probe;
        }
    }

    pe_log("CODM base not found via probe, using 0x100000000");
    return 0x100000000ULL;
}

// ============================================================================
//  ext_attach — main entry point
// ============================================================================

int ext_attach(void) {
    open_log_file();

    if (!ds_is_ready()) {
        pe_log("DarkSword not ready");
        close_log_file();
        return -1;
    }

    pe_log("=== ACLuna-External attach (pmap mode) ===");
    if (g_log_path) pe_log("LOG FILE: %s", g_log_path.UTF8String);
    pe_log("offsets: t1sz=%llu pac_mask=0x%llx smr=%llu",
           t1sz_boot, pac_mask, smr_base);
    pe_log("offsets: task_map=0x%x vm_map_hdr=0x%x",
           off_task_map, off_vm_map_hdr);
    pe_log("offsets: proc_ro=0x%x ro_task=0x%x p_pid=0x%x p_name=0x%x",
           off_proc_p_proc_ro, off_proc_ro_pr_task,
           off_proc_p_pid, off_proc_p_name);

    @try {
        // === STEP 1: Find CODM ===
        pe_log("[STEP 1] searching for CODM...");
        uint64_t codm_proc = find_codm_proc(&g_codm_pid);
        if (!codm_proc) {
            pe_log("CODM not found. Is the game running?");
            close_log_file();
            return -2;
        }
        pe_log("[STEP 1] CODM proc: 0x%llx pid=%d", codm_proc, g_codm_pid);

        // === STEP 2: Get CODM's task ===
        pe_log("[STEP 2] resolving CODM task...");
        g_codm_task_kaddr = safe_taskbyproc(codm_proc);
        if (!g_codm_task_kaddr) {
            g_codm_task_kaddr = taskbyproc(codm_proc);
        }
        if (!g_codm_task_kaddr || !ds_isvalid(g_codm_task_kaddr)) {
            pe_log("[STEP 2] FAILED — task invalid 0x%llx", g_codm_task_kaddr);
            close_log_file();
            return -3;
        }
        pe_log("[STEP 2] task: 0x%llx", g_codm_task_kaddr);

        // === STEP 3: Sandbox escape (GBox) ===
        pe_log("[STEP 3] sandbox escape...");
        uint64_t our_proc_kaddr = ds_get_our_proc();
        if (!our_proc_kaddr) our_proc_kaddr = proc_self();
        if (our_proc_kaddr) {
            int sbx_rc = sbx_escape(our_proc_kaddr);
            pe_log("[STEP 3] sbx_escape returned %d", sbx_rc);
        } else {
            pe_log("[STEP 3] no proc for sbx_escape, skipping");
        }

        // === STEP 4: Resolve pmap + physmap ===
        pe_log("[STEP 4] resolving vm_map -> pmap -> physmap...");

        // Read vm_map — strip PAC since xpaci is no-op on arm64 builds.
        uint64_t vm_map_raw = ds_kread64(g_codm_task_kaddr + off_task_map);
        uint64_t vm_map = kptr_strip_pac(vm_map_raw);
        pe_log("  vm_map: raw=0x%llx fixed=0x%llx (task+0x%x)",
               vm_map_raw, vm_map, off_task_map);
        if (!ds_isvalid(vm_map)) {
            pe_log("[STEP 4] FAILED — vm_map invalid");
            close_log_file();
            return -4;
        }

        g_codm_pmap = find_pmap_in_vm_map(vm_map);
        if (!g_codm_pmap || g_codm_ttep == 0 || g_physmap_offset == 0) {
            pe_log("[STEP 4] FAILED — pmap not found");
            close_log_file();
            return -4;
        }
        pe_log("[STEP 4] pmap=0x%llx ttep=0x%llx physmap=+0x%llx",
               g_codm_pmap, g_codm_ttep, g_physmap_offset);

        // === STEP 5: Test page table walk ===
        pe_log("[STEP 5] testing page table walk...");
        uint64_t test_va = 0x100000000ULL;
        uint64_t test_pa = pmap_walk_va(g_codm_ttep, test_va);
        pe_log("  VA 0x%llx -> PA 0x%llx", test_va, test_pa);
        if (test_pa) {
            uint64_t kva = pa_to_kva(test_pa);
            pe_log("  PA -> KVA 0x%llx (valid=%d)", kva, ds_isvalid(kva));
            if (ds_isvalid(kva)) {
                uint64_t val = ds_kread64(kva);
                pe_log("  read OK: 0x%llx", val);
            } else {
                pe_log("  WARNING: KVA not in valid range");
            }
        } else {
            pe_log("  VA 0x100000000 not mapped — will probe for base");
        }

        // === STEP 6: Resolve CODM base ===
        pe_log("[STEP 6] resolving CODM base...");
        g_codm_base = resolve_codm_base_kread();
        g_attached = true;
        pe_log("[DONE] attached to CODM pid=%d base=0x%llx", g_codm_pid, g_codm_base);
        close_log_file();
        return 0;

    } @catch (NSException *ex) {
        pe_log("EXCEPTION: %s — %s",
               ex.name.UTF8String, ex.reason.UTF8String);
        pe_log("Check offsets / t1sz_boot (currently %llu).", t1sz_boot);
        close_log_file();
        return -5;
    }
}

// ============================================================================
//  Public API
// ============================================================================

bool ext_is_attached(void)   { return g_attached; }
mach_port_t ext_codm_task(void) { return MACH_PORT_NULL; }  // no longer used
pid_t ext_codm_pid(void)    { return g_codm_pid; }
uint64_t ext_codm_base(void){ return g_codm_base; }

bool ext_read(uint64_t address, void *buffer, size_t size) {
    if (!g_attached || g_codm_ttep == 0 || g_physmap_offset == 0) return false;

    uint8_t *dst = (uint8_t *)buffer;
    uint64_t va  = address;
    size_t remaining = size;

    while (remaining > 0) {
        uint64_t pa = cached_pmap_walk(va);
        if (!pa) return false;

        uint64_t kva = pa_to_kva(pa);
        if (!ds_isvalid(kva)) return false;

        // Bytes until next page boundary.
        size_t page_left = 0x1000 - (va & 0xFFF);
        size_t chunk = (page_left < remaining) ? page_left : remaining;

        // Read chunk via kernel R/W, 8 bytes at a time.
        for (size_t i = 0; i < chunk; i += 8) {
            size_t n = (chunk - i >= 8) ? 8 : (chunk - i);
            uint64_t val = ds_kread64(kva + i);
            memcpy(dst + i, &val, n);
        }

        dst       += chunk;
        va        += chunk;
        remaining -= chunk;
    }
    return true;
}

uint64_t ext_read64(uint64_t address) {
    uint64_t val = 0;
    ext_read(address, &val, 8);
    return val;
}

uint32_t ext_read32(uint64_t address) {
    uint32_t val = 0;
    ext_read(address, &val, 4);
    return val;
}

float ext_readf(uint64_t address) {
    float val = 0;
    ext_read(address, &val, 4);
    return val;
}

uint64_t ext_readptr(uint64_t address) {
    uint64_t val = ext_read64(address);
    // Strip PAC bits for user-space pointers (39-bit VA on A14).
    val &= 0x0000007FFFFFFFFFULL;
    return val;
}
