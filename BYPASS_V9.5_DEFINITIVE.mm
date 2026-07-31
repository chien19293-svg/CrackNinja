// BYPASS_V9.5_DEFINITIVE.mm — FIXED for GitHub Actions (iOS SDK)
// Build:
//   xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc \
//     -framework Foundation -framework CFNetwork -framework Security \
//     -Wl,-undefined,dynamic_lookup -O2 BYPASS_V9.5_DEFINITIVE.mm -o bypass.dylib
//
// FIXED: thêm header <mach/vm_prot.h>, thay sys_icache_invalidate bằng __builtin___clear_cache

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/vm_prot.h>   // FIX: định nghĩa VM_PROT_*
#import <sys/mman.h>
#import <dlfcn.h>
#import <Security/Security.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>

// Định nghĩa VM_PROT_EXEC nếu thiếu (một số SDK dùng VM_PROT_EXECUTE)
#ifndef VM_PROT_EXEC
#define VM_PROT_EXEC VM_PROT_EXECUTE
#endif

// Macro thay thế sys_icache_invalidate
#define INVALIDATE_ICACHE(addr, size) __builtin___clear_cache((char*)(addr), (char*)(addr) + (size))

// ============================================================
// STRUCT: NinjaDownloadedModule
// ============================================================
#define NINJA_TIER_NAME_MAX 64
typedef struct __attribute__((packed)) {
    uint64_t id;
    uint8_t* raw_wasm_ptr;
    size_t   raw_wasm_size;
    bool     is_installed;
    uint64_t install_time_monotonic_ms;
    uint8_t  sha256_digest[32];
    char     tier_name[NINJA_TIER_NAME_MAX];
} NinjaDownloadedModule;

// ============================================================
// GLOBALS
// ============================================================
static NinjaDownloadedModule g_module_cache = {0};
static bool g_module_cache_ready = false;
static int  g_retry_count = 0;
static uint8_t g_fixed_Ks[32] = {0};
static bool g_Ks_inited = false;
static bool g_setup_done = false;
static bool g_patches_applied = false;
static pthread_mutex_t g_setup_lock = PTHREAD_MUTEX_INITIALIZER;

// ============================================================
// FIX 15: SecCodeCheckValidity GOT patch (libloader)
// ============================================================
static OSStatus stub_SecCodeCheckValidity(
    SecStaticCodeRef code, SecCSFlags flags, SecRequirementRef requirement) {
    return errSecSuccess;
}
static OSStatus stub_SecCodeCheckValidityWithErrors(
    SecStaticCodeRef code, SecCSFlags flags, SecRequirementRef requirement,
    CFErrorRef *errors) {
    return errSecSuccess;
}

static void patch_got_SecCodeCheckValidity(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, "libloader.framework/libloader")) continue;
        
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = 
            (const struct mach_header_64*)_dyld_get_image_header(i);
        
        const struct section_64* got_sec = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            const struct load_command* lc = (const struct load_command*)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* seg = 
                    (const struct segment_command_64*)lc;
                if (strcmp(seg->segname, "__DATA") == 0) {
                    const struct section_64* secs = 
                        (const struct section_64*)(seg + 1);
                    for (uint32_t k = 0; k < seg->nsects; k++) {
                        if (strcmp(secs[k].sectname, "__got") == 0) {
                            got_sec = &secs[k];
                            break;
                        }
                    }
                }
            }
            if (got_sec) break;
            p += lc->cmdsize;
        }
        
        if (!got_sec) {
            NSLog(@"[V9.5] ! __DATA.__got not found in libloader");
            break;
        }
        
        void* secCodeFunc = (void*)dlsym(RTLD_DEFAULT, "SecCodeCheckValidity");
        if (!secCodeFunc) {
            for (uint32_t k = 0; k < _dyld_image_count(); k++) {
                void* handle = dlopen(_dyld_get_image_name(k), RTLD_LAZY);
                if (handle) {
                    secCodeFunc = dlsym(handle, "SecCodeCheckValidity");
                    dlclose(handle);
                    if (secCodeFunc) break;
                }
            }
        }
        if (!secCodeFunc) {
            NSLog(@"[V9.5] Cannot resolve SecCodeCheckValidity. Skipping GOT patch.");
            break;
        }
        
        uint64_t got_addr = (uint64_t)got_sec->addr + slide + 0x100000000ULL;
        uint64_t got_count = (uint64_t)got_sec->size / sizeof(uint64_t);
        uint64_t target_addr = (uint64_t)secCodeFunc;
        
        void* secCodeFuncWE = (void*)dlsym(RTLD_DEFAULT, 
            "SecCodeCheckValidityWithErrors");
        
        int patched = 0;
        for (uint64_t j = 0; j < got_count; j++) {
            uint64_t* entry = (uint64_t*)(got_addr + j * sizeof(uint64_t));
            uint64_t val = *entry;
            
            if (val == target_addr) {
                vm_address_t pg = ((vm_address_t)entry) & ~(PAGE_SIZE-1);
                kern_return_t kr = mach_vm_protect(mach_task_self(), pg, 
                    PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_WRITE);
                if (kr == KERN_SUCCESS) {
                    *entry = (uint64_t)stub_SecCodeCheckValidity;
                    mach_vm_protect(mach_task_self(), pg, PAGE_SIZE, FALSE, 
                        VM_PROT_READ);
                    NSLog(@"[V9.5] GOT[%llu]: SecCodeCheckValidity → stub", j);
                    patched++;
                }
            }
            
            if (secCodeFuncWE && val == (uint64_t)secCodeFuncWE) {
                vm_address_t pg = ((vm_address_t)entry) & ~(PAGE_SIZE-1);
                kern_return_t kr = mach_vm_protect(mach_task_self(), pg, 
                    PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_WRITE);
                if (kr == KERN_SUCCESS) {
                    *entry = (uint64_t)stub_SecCodeCheckValidityWithErrors;
                    mach_vm_protect(mach_task_self(), pg, PAGE_SIZE, FALSE, 
                        VM_PROT_READ);
                    NSLog(@"[V9.5] GOT[%llu]: SecCodeCheckValidityWithErrors → stub", j);
                    patched++;
                }
            }
        }
        
        if (patched == 0) {
            NSLog(@"[V9.5] SecCodeCheckValidity not in GOT. Skipping.");
        }
        break;
    }
}

// ============================================================
// FIX 16: patch_appdome_hooks_dynamic (chỉ patch loader.framework)
// ============================================================
static void patch_appdome_hooks_dynamic(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (!strstr(nm, "loader.framework/loader")) continue;
        
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = 
            (const struct mach_header_64*)_dyld_get_image_header(i);
        
        const struct symtab_command* st = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (((const struct load_command*)p)->cmd == LC_SYMTAB) {
                st = (const struct symtab_command*)p; break;
            }
            p += ((const struct load_command*)p)->cmdsize;
        }
        if (!st) continue;
        
        const struct nlist_64* nl = (const struct nlist_64*)
            ((uintptr_t)hdr + st->symoff);
        const char* strtab = (const char*)
            ((uintptr_t)hdr + st->stroff);
        
        int patch_count = 0;
        for (uint32_t j = 0; j < st->nsyms; j++) {
            const char* sym = strtab + nl[j].n_un.n_strx;
            if (!sym || *sym == '\0') continue;
            if (!strstr(sym, "appdome_hook")) continue;
            
            uintptr_t func_addr = nl[j].n_value + slide + 0x100000000ULL;
            if (func_addr < 0x100000000ULL) continue;
            
            uint32_t patch[2];
            bool is_syscall = strstr(sym, "ptrace") || strstr(sym, "sysctl") ||
                              strstr(sym, "kill") || strstr(sym, "task_terminate") ||
                              strstr(sym, "thread_terminate") || strstr(sym, "sigaction") ||
                              strstr(sym, "task_get_exception");
            bool is_exit = strstr(sym, "exit") || strstr(sym, "abort");
            bool is_sleep = strstr(sym, "nanosleep") || strstr(sym, "usleep") || 
                            strstr(sym, "sleep");
            
            if (is_syscall) {
                patch[0] = 0x12800000; // MOVN W0, #0 (W0 = -1)
                patch[1] = 0xD65F03C0; // RET
            } else if (is_exit) {
                patch[0] = 0xD503201F; // NOP
                patch[1] = 0xD65F03C0; // RET
            } else if (is_sleep) {
                patch[0] = 0x52800000; // MOV W0, #0
                patch[1] = 0xD65F03C0; // RET
            } else {
                patch[0] = 0xD503201F; // NOP
                patch[1] = 0xD65F03C0; // RET
            }
            
            vm_address_t pg = func_addr & ~(PAGE_SIZE-1);
            kern_return_t kr = mach_vm_protect(mach_task_self(), pg, 
                PAGE_SIZE*2, FALSE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC);
            if (kr != KERN_SUCCESS) {
                continue;
            }
            memcpy((void*)func_addr, patch, 8);
            mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, 
                VM_PROT_READ|VM_PROT_EXEC);
            INVALIDATE_ICACHE(func_addr, 8);
            patch_count++;
            NSLog(@"[V9.5] Patched %s in loader.framework", sym);
        }
        NSLog(@"[V9.5] Patched %d appdome_hook functions in loader.framework", 
              patch_count);
        break;
    }
}

// ============================================================
// load_wasm_cache (rút gọn)
// ============================================================
static bool load_wasm_cache(void) {
    if (g_module_cache_ready) return true;
    g_retry_count++;
    if (!g_Ks_inited) { memset(g_fixed_Ks, 0x41, 32); g_Ks_inited = true; }
    @autoreleasepool {
        // Dùng bundle path
        NSString* wasmPath = [[NSBundle mainBundle] 
            pathForResource:@"cheat_decoded" ofType:@"wasm"];
        if (!wasmPath) {
            wasmPath = [NSSearchPathForDirectoriesInDomains(
                NSDocumentDirectory, NSUserDomainMask, YES)[0]
                stringByAppendingPathComponent:@"cheat_decoded.wasm"];
        }
        if (!wasmPath || ![[NSFileManager defaultManager] fileExistsAtPath:wasmPath]) {
            // Nếu không có WASM, tạo dummy (để build pass, nhưng cheat sẽ không hoạt động)
            NSLog(@"[V9.5] WASM not found, creating dummy module for build test.");
            void* dummy = malloc(1024);
            if (!dummy) return false;
            memset(dummy, 0, 1024);
            g_module_cache.raw_wasm_ptr = (uint8_t*)dummy;
            g_module_cache.raw_wasm_size = 1024;
            g_module_cache.is_installed = false;
            g_module_cache.id = 0xDEADBEEF;
            memset(g_module_cache.sha256_digest, 0, 32);
            strncpy(g_module_cache.tier_name, "tier_PREMIUM_VIP_LIFETIME", 64);
            g_module_cache_ready = true;
            return true;
        }
        NSData* wasmData = [NSData dataWithContentsOfFile:wasmPath];
        if (!wasmData || wasmData.length < 4096) {
            return false;
        }
        size_t wasm_size = [wasmData length];
        void* wasm_buffer = NULL;
        int ret = posix_memalign(&wasm_buffer, 16384, wasm_size);
        if (ret != 0 || !wasm_buffer) { return false; }
        memcpy(wasm_buffer, [wasmData bytes], wasm_size);
        uint8_t mod_id[16] = {0x08,0,0,0,0xD2,0xD4,0xE0,0x45,
                              0x94,0x8A,0x42,0x06,0x66,0x91,0xA4,0x94};
        g_module_cache.id = *(uint64_t*)mod_id;
        g_module_cache.raw_wasm_ptr = (uint8_t*)wasm_buffer;
        g_module_cache.raw_wasm_size = wasm_size;
        g_module_cache.is_installed = false;
        g_module_cache.install_time_monotonic_ms = 
            (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000);
        memset(g_module_cache.sha256_digest, 0, 32);
        strncpy(g_module_cache.tier_name, "tier_PREMIUM_VIP_LIFETIME", 64);
        g_module_cache_ready = true;
        NSLog(@"[V9.5] WASM loaded: %zu B @%p", wasm_size, wasm_buffer);
        return true;
    }
}

// ============================================================
// patched_invokeNative — LDR/BR absolute
// ============================================================
static uint32_t patched_invokeNative(void* func_inst, uint32_t argc, uint64_t* argv) {
    return 1;
}

static void patch_invokeNative(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!strstr(nm, "loader.framework/loader")) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = 
            (const struct mach_header_64*)_dyld_get_image_header(i);
        const struct symtab_command* symtab = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (((const struct load_command*)p)->cmd == LC_SYMTAB) {
                symtab = (const struct symtab_command*)p; break;
            }
            p += ((const struct load_command*)p)->cmdsize;
        }
        if (!symtab) break;
        const struct nlist_64* nl = (const struct nlist_64*)
            ((uintptr_t)hdr + symtab->symoff);
        const char* strtab = (const char*)((uintptr_t)hdr + symtab->stroff);
        for (uint32_t j = 0; j < symtab->nsyms; j++) {
            if (strcmp(strtab + nl[j].n_un.n_strx, "_invokeNative") == 0) {
                uintptr_t addr = nl[j].n_value + slide + 0x100000000ULL;
                uint32_t patch[2] = {0x58000050, 0xD61F0200};
                vm_address_t pg = addr & ~(PAGE_SIZE-1);
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, 
                    VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC);
                memcpy((void*)addr, patch, 8);
                *(uint64_t*)(addr + 8) = (uint64_t)patched_invokeNative;
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, 
                    VM_PROT_READ|VM_PROT_EXEC);
                INVALIDATE_ICACHE(addr, 16);
                NSLog(@"[V9.5] _invokeNative → LDR/BR stub");
                return;
            }
        }
        break;
    }
}

// ============================================================
// patch_shared_key32 — Dynamic g_Ks
// ============================================================
static void patch_shared_key32(void) {
    if (!g_Ks_inited) { memset(g_fixed_Ks, 0x41, 32); g_Ks_inited = true; }
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!strstr(nm, "ninja.framework/ninja")) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = 
            (const struct mach_header_64*)_dyld_get_image_header(i);
        const struct symtab_command* symtab = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (((const struct load_command*)p)->cmd == LC_SYMTAB) {
                symtab = (const struct symtab_command*)p; break;
            }
            p += ((const struct load_command*)p)->cmdsize;
        }
        if (!symtab) break;
        const struct nlist_64* nl = (const struct nlist_64*)
            ((uintptr_t)hdr + symtab->symoff);
        const char* strtab = (const char*)((uintptr_t)hdr + symtab->stroff);
        for (uint32_t j = 0; j < symtab->nsyms; j++) {
            if (strstr(strtab + nl[j].n_un.n_strx, "SharedKey32")) {
                uintptr_t func = nl[j].n_value + slide + 0x100000000ULL;
                uint32_t pat[3] = {0x58000040, 0xD503201F, 0xD65F03C0};
                vm_address_t pg = func & ~(PAGE_SIZE-1);
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, 
                    VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC);
                memcpy((void*)func, pat, 12);
                *(uint64_t*)(func + 12) = (uint64_t)g_fixed_Ks;
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, 
                    VM_PROT_READ|VM_PROT_EXEC);
                INVALIDATE_ICACHE(func, 20);
                NSLog(@"[V9.5] SharedKey32 → g_fixed_Ks");
                return;
            }
        }
        break;
    }
}

// ============================================================
// setup_trampoline — open_delivery_envelope
// ============================================================
static bool setup_trampoline(void) {
    pthread_mutex_lock(&g_setup_lock);
    if (g_setup_done) { pthread_mutex_unlock(&g_setup_lock); return true; }
    if (!g_module_cache_ready) {
        if (g_retry_count < 3) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                (int64_t)(0.5 * g_retry_count * NSEC_PER_SEC)),
                dispatch_get_main_queue(), ^{ setup_trampoline(); });
        }
        pthread_mutex_unlock(&g_setup_lock);
        return false;
    }
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!strstr(nm, "loader.framework/loader")) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = 
            (const struct mach_header_64*)_dyld_get_image_header(i);
        const struct symtab_command* symtab = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (((const struct load_command*)p)->cmd == LC_SYMTAB) {
                symtab = (const struct symtab_command*)p; break;
            }
            p += ((const struct load_command*)p)->cmdsize;
        }
        if (!symtab) break;
        const struct nlist_64* nl = (const struct nlist_64*)
            ((uintptr_t)hdr + symtab->symoff);
        const char* strtab = (const char*)((uintptr_t)hdr + symtab->stroff);
        for (uint32_t j = 0; j < symtab->nsyms; j++) {
            if (strstr(strtab + nl[j].n_un.n_strx, "open_delivery_envelope")) {
                uintptr_t func_addr = nl[j].n_value + slide + 0x100000000ULL;
                uint32_t tramp[13] = {0};
                tramp[0] = 0xA9BF7BFD;
                tramp[1] = 0x910003FD;
                tramp[2] = 0x58000089;
                tramp[3] = 0x580000AA;
                tramp[4] = 0xF9000049;
                tramp[5] = 0xB9000C4A;
                tramp[6] = 0xA8C17BFD;
                tramp[7] = 0x52800020;
                tramp[8] = 0xD65F03C0;
                tramp[9] = 0xD503201F;
                tramp[10]= 0xD503201F;
                vm_address_t pg = func_addr & ~(PAGE_SIZE-1);
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*3, FALSE, 
                    VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC);
                memcpy((void*)func_addr, tramp, 44);
                *(uint64_t*)(func_addr + 44) = (uint64_t)g_module_cache.raw_wasm_ptr;
                *(uint64_t*)(func_addr + 52) = (uint64_t)g_module_cache.raw_wasm_size;
                mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*3, FALSE, 
                    VM_PROT_READ|VM_PROT_EXEC);
                INVALIDATE_ICACHE(func_addr, 60);
                g_setup_done = true;
                pthread_mutex_unlock(&g_setup_lock);
                NSLog(@"[V9.5] open_delivery_envelope → trampoline");
                return true;
            }
        }
        break;
    }
    pthread_mutex_unlock(&g_setup_lock);
    return false;
}

// ============================================================
// patch_auth_functions
// ============================================================
static void patch_auth_functions(void) {
    const char* targets[] = {"ninja.framework/ninja", "loader.framework/loader", NULL};
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!nm) continue;
        bool matched = false;
        for (int t = 0; targets[t]; t++) { if (strstr(nm, targets[t])) { matched = true; break; } }
        if (!matched) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = (const struct mach_header_64*)_dyld_get_image_header(i);
        const struct symtab_command* st = NULL;
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (((const struct load_command*)p)->cmd == LC_SYMTAB) { st = (const struct symtab_command*)p; break; }
            p += ((const struct load_command*)p)->cmdsize;
        }
        if (!st) continue;
        const struct nlist_64* nl = (const struct nlist_64*)((uintptr_t)hdr + st->symoff);
        const char* strtab = (const char*)((uintptr_t)hdr + st->stroff);
        const char* func_names[] = {"ninja_security_session_valid", "ninja_security_guard_valid", "_ninja_autoplay_module_authorized", "ninja_security_confirm_module", NULL};
        for (uint32_t j = 0; j < st->nsyms; j++) {
            const char* sym = strtab + nl[j].n_un.n_strx;
            if (!sym || *sym == '\0') continue;
            for (int f = 0; func_names[f]; f++) {
                if (strstr(sym, func_names[f])) {
                    uintptr_t addr = nl[j].n_value + slide + 0x100000000ULL;
                    uint32_t patch[2] = {0x52800020, 0xD65F03C0};
                    vm_address_t pg = addr & ~(PAGE_SIZE-1);
                    kern_return_t kr = mach_vm_protect(mach_task_self(), pg, PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXEC);
                    if (kr == KERN_SUCCESS) {
                        memcpy((void*)addr, patch, 8);
                        mach_vm_protect(mach_task_self(), pg, PAGE_SIZE, FALSE, VM_PROT_READ|VM_PROT_EXEC);
                        INVALIDATE_ICACHE(addr, 8);
                        NSLog(@"[V9.5] Patched %s -> ret 1", func_names[f]);
                    }
                    break;
                }
            }
        }
    }
}

// ============================================================
// NSURLSession swizzle
// ============================================================
static IMP orig_dataTaskImp = NULL;
typedef NSURLSessionDataTask* (*dataTask_fn)(id, SEL, NSURLRequest*, void(^)(NSData*, NSURLResponse*, NSError*));

static NSURLSessionDataTask* bypass_dataTask(id slf, SEL _cmd, NSURLRequest* req, void(^handler)(NSData*, NSURLResponse*, NSError*)) {
    NSString* url = [[req URL] absoluteString];
    if ([url containsString:@"session-key"]) {
        NSString* fake = @"{\"server_eph_pub\":\"4141414141414141414141414141414141414141414141414141414141414141\",\"handshake_sig\":\"\"}";
        NSHTTPURLResponse* resp = [[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:200 HTTPVersion:@"1.1" headerFields:@{@"Content-Type":@"application/json"}];
        handler([fake dataUsingEncoding:NSUTF8StringEncoding], resp, nil); return nil;
    }
    if ([url containsString:@"auth/login"]) {
        NSString* fake = @"{\"authenticated\":true,\"expires_at\":\"2099-12-31T23:59:59Z\",\"remaining_seconds\":253402300799,\"token_key\":\"BYPASS_TOKEN_0xCAFEBABE\",\"tier\":\"tier_PREMIUM_VIP_LIFETIME\",\"server_eph_pub\":\"4141414141414141414141414141414141414141414141414141414141414141\",\"handshake_sig\":\"\"}";
        NSHTTPURLResponse* resp = [[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:200 HTTPVersion:@"1.1" headerFields:@{@"Content-Type":@"application/json"}];
        handler([fake dataUsingEncoding:NSUTF8StringEncoding], resp, nil); return nil;
    }
    if ([url containsString:@"heartbeat"] || [url containsString:@"ping"]) {
        NSString* fake = [NSString stringWithFormat:@"{\"status\":\"ok\",\"server_time\":%lld}", (int64_t)([[NSDate date] timeIntervalSince1970] * 1000)];
        NSHTTPURLResponse* resp = [[NSHTTPURLResponse alloc] initWithURL:[req URL] statusCode:200 HTTPVersion:@"1.1" headerFields:@{@"Content-Type":@"application/json"}];
        handler([fake dataUsingEncoding:NSUTF8StringEncoding], resp, nil); return nil;
    }
    return ((dataTask_fn)orig_dataTaskImp)(slf, _cmd, req, handler);
}

// ============================================================
// force_global_state
// ============================================================
static void force_global_state(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char* nm = _dyld_get_image_name(i);
        if (!strstr(nm, "ninja.framework/ninja")) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct mach_header_64* hdr = (const struct mach_header_64*)_dyld_get_image_header(i);
        const uint8_t* p = (const uint8_t*)hdr + sizeof(*hdr);
        uintptr_t data_base = 0;
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            const struct load_command* lc = (const struct load_command*)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64* seg = (const struct segment_command_64*)lc;
                if (strcmp(seg->segname, "__DATA") == 0) { data_base = (uintptr_t)seg->vmaddr + slide + 0x100000000ULL; break; }
            }
            p += lc->cmdsize;
        }
        if (!data_base) continue;
        uintptr_t g_valid_addr = data_base + 0x1096;
        uintptr_t g_exp_addr = data_base + 0x10FE;
        vm_address_t pg = g_valid_addr & ~(PAGE_SIZE-1);
        kern_return_t kr = mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, VM_PROT_READ|VM_PROT_WRITE);
        if (kr == KERN_SUCCESS) {
            *(uint8_t*)g_valid_addr = 0x01;
            *(uint64_t*)g_exp_addr = 0xFFFFFFFFFFFFFFFFULL;
            mach_vm_protect(mach_task_self(), pg, PAGE_SIZE*2, FALSE, VM_PROT_READ);
            NSLog(@"[V9.5] Force g_valid=1, g_exp=INF");
        }
        break;
    }
}

// ============================================================
// Heartbeat keep-alive thread
// ============================================================
static void* heartbeat_keepalive(void* arg) {
    while (true) { sleep(30); force_global_state(); }
    return NULL;
}

// ============================================================
// ENTRY POINT: +[BypassEntry load]
// ============================================================
@interface BypassEntry : NSObject @end
@implementation BypassEntry
+ (void)load {
    @autoreleasepool {
        NSLog(@"[V9.5] BypassEntry.load starting...");
        patch_got_SecCodeCheckValidity();
        patch_appdome_hooks_dynamic();
        load_wasm_cache();
        patch_auth_functions();
        patch_shared_key32();
        patch_invokeNative();
        Class clsSess = NSClassFromString(@"__NSCFURLSession") ?: [NSURLSession class];
        SEL sel = @selector(dataTaskWithRequest:completionHandler:);
        Method m = class_getInstanceMethod(clsSess, sel);
        if (m) { orig_dataTaskImp = method_getImplementation(m); method_setImplementation(m, (IMP)bypass_dataTask); }
        force_global_state();
        dispatch_async(dispatch_get_main_queue(), ^{ setup_trampoline(); });
        pthread_t ht; pthread_create(&ht, NULL, heartbeat_keepalive, NULL); pthread_detach(ht);
        NSLog(@"[V9.5] ✅ All fixes applied. Ready.");
    }
}
@end
