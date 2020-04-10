//
//  sbpwn6.c
//
//  Created by @dora2_yururi on 2020/03/20.
//  Copyright (c) 2019 - 2020 dora2_yururi. All rights reserved.
//


#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/loader.h>
#include <sys/utsname.h>

#include "syscall.h"
#include "patchfinder.h"

#define DEFAULT_KERNEL_SLIDE    0x80000000
#define KDUMP_SIZE              0xF00000
#define CHUNK_SIZE              0x800

mach_port_t tfp0=0;

/* qwertyoruiop's yalu102 */
void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

/* kernel read/write */
uint32_t rk32(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t wk32(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}
uint32_t wk16(uint32_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}
uint32_t wk8(uint32_t addr, uint8_t val) {
    copyout(addr, &val, 1);
    return val;
}

/* tfp0 */
mach_port_t get_kernel_task() {
    task_t kernel_task;
    if (KERN_SUCCESS != task_for_pid(mach_task_self(), 0, &kernel_task)) {
        return -1;
    }
    return kernel_task;
}

/* kbase */
vm_address_t get_kernel_base() {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    while (1) {
        if (KERN_SUCCESS != vm_region_recurse_64(tfp0, &addr, &size, &depth, (vm_region_info_t) & info, &info_count))
            break;
        if (size > 1024 * 1024 * 1024) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MH_MAGIC) {
                addr -= 0x200000;
                vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MH_MAGIC) {
                    break;
                }
            }
            vm_address_t kbase = addr + 0x1000;
            return kbase;
        }
        addr += size;
    }
    return -1;
}

/* read kmem */
void read_kmem(vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    vm_address_t addr;
    vm_address_t e;
    for (addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

/* pmap */
typedef struct pmap_partial_t {
    uint32_t tte_virt;
    uint32_t tte_phys;
    /*
     * ...
     */
} pmap_partial_t;

// evasi0n6
void set_kernel_page_writable_tfp(int type, uint32_t kernel_region, uint32_t pmap_location, uint32_t flush_dcache, uint32_t invalidate_tlb, uint32_t page)
{
    static int is_first_run = 1;

    static uint32_t virtual_start;
    static uint32_t first_level_page_table_location;
    static uint32_t first_level_page_table_physical_location;
    static uint32_t first_level_page_table_entries;
    static uint32_t physical_start;
    static uint32_t* first_level_page_table;
    
    if(is_first_run)
    {
        virtual_start = kernel_region;
        
        uint32_t pmap_data[2];
        copyin(pmap_data, pmap_location, sizeof(pmap_data));
        first_level_page_table_location = pmap_data[0];
        first_level_page_table_physical_location = pmap_data[1];
        first_level_page_table_entries = rk32(pmap_location + 0x54);
        
        physical_start = first_level_page_table_physical_location - (first_level_page_table_location - virtual_start);
        
        first_level_page_table = (uint32_t*) malloc(first_level_page_table_entries * sizeof(uint32_t));
        memset(first_level_page_table, 0, first_level_page_table_entries * sizeof(uint32_t));
        
        is_first_run = 0;
    }
    
    uint32_t i = page >> 20;
    uint32_t entry = first_level_page_table[i];
    if(entry == 0)
    {
        first_level_page_table[i] = entry = rk32(first_level_page_table_location + (sizeof(entry) * i));
    }
    
    {
        if((entry & 0x3) == 2)
        {
            if((i << 20) == ((page >> 20) << 20))
            {
                entry &= ~(1 << 15);
                wk32(first_level_page_table_location + (sizeof(entry) * i), entry);
                goto end;
            }
        } else if((entry & 0x3) == 1)
        {
            uint32_t page_table_address = (entry >> 10) << 10;
            uint32_t virtual_page_table_address = page_table_address - physical_start + virtual_start;
            
            int j = (page >> 12) & 0xFF;
            uint32_t second_level_entry = rk32(virtual_page_table_address + (sizeof(second_level_entry) * j));
            {
                if((second_level_entry & 0x3) == 1)
                {
                    if(((i << 20) + (j << 12)) == page)
                    {
                        second_level_entry &= ~(1 << 9);
                        wk32(virtual_page_table_address + (sizeof(second_level_entry) * j), second_level_entry);
                        goto end;
                    }
                } else if((second_level_entry & 0x2) == 2)
                {
                    if(((i << 20) + (j << 12)) == page)
                    {
                        second_level_entry &= ~(1 << 9);
                        wk32(virtual_page_table_address + (sizeof(second_level_entry) * j), second_level_entry);
                        goto end;
                    }
                }
            }
        }
    }
    
end:
    if(type == 1)
    {
        syscall(0, flush_dcache, 0, 0, 0, 0);
        syscall(0, invalidate_tlb, 0, 0, 0, 0);
    } else
    {
        usleep(10000); // Prevent kernel panic
    }
}

// Not used
uint32_t physalloc(uint32_t size) {
    uint32_t ret = 0;
    vm_allocate(tfp0, (mach_vm_address_t*) &ret, size, VM_FLAGS_ANYWHERE);
    return ret;
}

// evasi0n6
void sb_patch(uint32_t pmap,
              uint32_t flush_dcache, uint32_t invalidate_tlb,
              uint32_t kbase, uint32_t patch_location, uint32_t vn_getpath, uint32_t memcmp_addr)
{
    extern void sb_evaluate_trampoline();
    extern uint32_t sb_evaluate_trampoline_hook_address;
    extern uint32_t sb_evaluate_trampoline_len;
    
    extern void sb_evaluate_hook();
    extern uint32_t sb_evaluate_hook_orig_addr;
    extern uint32_t sb_evaluate_hook_vn_getpath;
    extern uint32_t sb_evaluate_hook_memcmp;
    extern uint32_t sb_evaluate_hook_len;
    
    uint16_t bx_r9;
    uint32_t sb_payload_addr;
    uint32_t max_size_of_possible_overwritten_instructions;
    uint32_t size_of_possible_overwritten_instructions;
    uint32_t hook_size;
    
    uint8_t* sb_evaluate_trampoline_addr;
    uint8_t* sb_evaluate_hook_addr;
    uint8_t* trampoline;
    uint8_t* overwritten_instructions;
    uint8_t* hook;
    uint16_t* current_instruction;
    
    bx_r9 = 0x4748;
    
    // offset
    sb_payload_addr = kbase + 0xc00;
    printf("sb_payload_addr\t0x%08x\n", sb_payload_addr);
    
    // code
    sb_evaluate_trampoline_addr = (uint8_t*)(((intptr_t)&sb_evaluate_trampoline) & ~1);
    sb_evaluate_hook_addr = (uint8_t*)(((intptr_t)&sb_evaluate_hook) & ~1);
    
    trampoline = (uint8_t*) malloc(sb_evaluate_trampoline_len);
    memcpy(trampoline, sb_evaluate_trampoline_addr, sb_evaluate_trampoline_len);
    *((uint32_t*)(trampoline + ((intptr_t)&sb_evaluate_trampoline_hook_address - (intptr_t)sb_evaluate_trampoline_addr))) = sb_payload_addr + 1;
    
    max_size_of_possible_overwritten_instructions = sb_evaluate_trampoline_len + 4;
    overwritten_instructions = (uint8_t*) malloc(max_size_of_possible_overwritten_instructions);
    copyin(overwritten_instructions, patch_location, max_size_of_possible_overwritten_instructions);
    
    if(memcmp(overwritten_instructions, trampoline, sb_evaluate_trampoline_len) == 0)
    {
        // Already patched
        printf("sb_evaluate already patched\n");
        free(overwritten_instructions);
        free(trampoline);
        return;
    }
    
    size_of_possible_overwritten_instructions = 0;
    current_instruction = (uint16_t*) overwritten_instructions;
    while(((intptr_t)current_instruction - (intptr_t)overwritten_instructions) < sb_evaluate_trampoline_len)
    {
        if((*current_instruction & 0xe000) == 0xe000 && (*current_instruction & 0x1800) != 0x0)
        {
            size_of_possible_overwritten_instructions += 4;
            current_instruction += 2;
        } else
        {
            size_of_possible_overwritten_instructions += 2;
            current_instruction += 1;
        }
    }
    
    hook_size = ((sb_evaluate_hook_len + size_of_possible_overwritten_instructions + sizeof(bx_r9) + 3) / 4) * 4;
    hook = (uint8_t*) malloc(hook_size);
    memcpy(hook, sb_evaluate_hook_addr, sb_evaluate_hook_len);
    memcpy(hook + sb_evaluate_hook_len, overwritten_instructions, size_of_possible_overwritten_instructions);
    memcpy(hook + sb_evaluate_hook_len + size_of_possible_overwritten_instructions, &bx_r9, sizeof(bx_r9));
 
    *((uint32_t*)(hook + ((intptr_t)&sb_evaluate_hook_orig_addr - (intptr_t)sb_evaluate_hook_addr))) = patch_location + size_of_possible_overwritten_instructions + 1;
    *((uint32_t*)(hook + ((intptr_t)&sb_evaluate_hook_vn_getpath - (intptr_t)sb_evaluate_hook_addr))) = vn_getpath;
    *((uint32_t*)(hook + ((intptr_t)&sb_evaluate_hook_memcmp - (intptr_t)sb_evaluate_hook_addr))) = memcmp_addr;
    
    // write sandbox payload
    set_kernel_page_writable_tfp(1, kbase, pmap, flush_dcache, invalidate_tlb, sb_payload_addr & ~0xFFF);
    copyout(sb_payload_addr, hook, hook_size);
    
    // hook sb_evaluate
    printf("hook sb_evaluate\n");
    set_kernel_page_writable_tfp(1, kbase, pmap, flush_dcache, invalidate_tlb, patch_location & ~0xFFF);
    copyout(patch_location, trampoline, sb_evaluate_trampoline_len);
    
    // flush_dcache
    syscall(0, flush_dcache, 0, 0, 0, 0);
    
    printf("sandbox: done\n");
    
    free(overwritten_instructions);
    free(trampoline);
    free(hook);
}

int main(){
    
    uint32_t kbase;
    void *kdump;
    size_t ksize;
    
    uint32_t data;
    uint32_t pmap;
    uint32_t pmap_location;
    
    uint32_t flush_dcache;
    uint32_t invalidate_tlb;
    uint32_t patch_location;
    uint32_t vn_getpath;
    uint32_t memcmp_addr;
    uint32_t syscall_zero;
    uint32_t syscall0_start;
    
    uint32_t sz;
    pointer_t buf;
    uint32_t tte_virt;
    uint32_t tte_phys;
    
    uint32_t shellcode;
    
    // start jb
    tfp0 = get_kernel_task();
    printf("tfp0\t\t0x%08x\n", tfp0);
    
    kbase = get_kernel_base();
    printf("kbase\t\t0x%08x\n", kbase);
    
    ksize = KDUMP_SIZE;
    
    kdump = malloc(ksize);
    read_kmem(kbase, kdump, ksize);
    
    // pmap
    pmap = kbase + find_pmap_location(kbase, kdump, ksize);
    pmap_location = rk32(pmap);
    printf("pmap\t\t0x%08x\n", pmap);
    printf("pmap_location\t0x%08x\n", pmap_location);
    
    // koffset
    flush_dcache = kbase + find_flush_dcache(kbase, kdump, ksize);
    invalidate_tlb = kbase + find_invalidate_tlb(kbase, kdump, ksize);
    patch_location = kbase + find_sb_patch(kbase, kdump, ksize);
    vn_getpath = kbase + find_vn_getpath(kbase, kdump, ksize);
    memcmp_addr = kbase + find_memcmp(kbase, kdump, ksize);
    syscall_zero = kbase + find_syscall0(kbase, kdump, ksize);
    
    printf("flush_dcache\t0x%08x\n", flush_dcache);
    printf("invalidate_tlb\t0x%08x\n", invalidate_tlb);
    printf("sb_patch\t0x%08x\n", patch_location);
    printf("vn_getpath\t0x%08x\n", vn_getpath);
    printf("memcmp_addr\t0x%08x\n", memcmp_addr);
    printf("syscall0\t0x%08x\n", syscall_zero);
    
    // shellcode
    shellcode = kbase + 0xb00;
    //shellcode = physalloc(0x18);
    printf("shellcode\t0x%08x\n", shellcode);
    
    set_kernel_page_writable_tfp(0, kbase, pmap_location, flush_dcache, invalidate_tlb, shellcode & ~0xfff);
    usleep(10000);
    
    wk16(shellcode   , 0xb5f0); // push   {r4-r7, lr}
    wk16(shellcode +2, 0x1c15); // adds   r5, r2, #0x0
    wk16(shellcode +4, 0x1c0e); // adds   r6, r1, #0x0
    wk16(shellcode +6, 0x6834); // ldr    r4, [r6]
    wk16(shellcode +8, 0x6870); // ldr    r0, [r6, #0x4]
    wk16(shellcode+10, 0x68b1); // ldr    r1, [r6, #0x8]
    wk16(shellcode+12, 0x68f2); // ldr    r2, [r6, #0xc]
    wk16(shellcode+14, 0x6933); // ldr    r3, [r6, #0x10]
    wk16(shellcode+16, 0x47a0); // blx    r4
    wk16(shellcode+18, 0x6028); // str    r0, [r5]
    wk16(shellcode+20, 0x2000); // movs   r0, #0x0
    wk16(shellcode+22, 0xbdf0); // pop    {r4-r7, pc}
    
    //vm_protect(tfp0, shellcode, 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    
    // backup
    struct sysent syscall0;
    struct sysent saved_syscall0;
    syscall0_start = syscall_zero - __builtin_offsetof(struct sysent, sy_call);
    copyin(&saved_syscall0, syscall0_start, sizeof(saved_syscall0));
    memcpy(&syscall0, &saved_syscall0, sizeof(syscall0));
    
    // hook syscall
    syscall0.sy_narg = 5;
    syscall0.sy_call = shellcode + 1;
    syscall0.sy_arg_bytes = 5 * sizeof(uint32_t);
    
    set_kernel_page_writable_tfp(0, kbase, pmap_location, flush_dcache, invalidate_tlb, syscall0_start & ~0xfff);
    usleep(10000);
    
    wk16(syscall0_start, syscall0.sy_narg);
    wk32(syscall0_start+4, syscall0.sy_call);
    wk32(syscall0_start+20, syscall0.sy_arg_bytes);
    
    // flush_dcache
    syscall(0, flush_dcache, 0, 0, 0, 0);
    syscall(0, invalidate_tlb, 0, 0, 0, 0);
    
    printf("shellcode: done\n");
    
    // sandbox
    sb_patch(pmap_location,
             flush_dcache, invalidate_tlb,
             kbase, patch_location, vn_getpath, memcmp_addr);
    
    // unpatch syscall
    wk16(syscall0_start, saved_syscall0.sy_narg);
    wk32(syscall0_start+4, saved_syscall0.sy_call);
    wk32(syscall0_start+20, saved_syscall0.sy_arg_bytes);
    
    wk16(shellcode   , 0);
    wk16(shellcode +2, 0);
    wk16(shellcode +4, 0);
    wk16(shellcode +6, 0);
    wk16(shellcode +8, 0);
    wk16(shellcode+10, 0);
    wk16(shellcode+12, 0);
    wk16(shellcode+14, 0);
    wk16(shellcode+16, 0);
    wk16(shellcode+18, 0);
    wk16(shellcode+20, 0);
    wk16(shellcode+22, 0);
    
    free(kdump);
    
    printf("JB: done\n");
    
    return 0;
}
