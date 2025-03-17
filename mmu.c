#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

// Typedefs
typedef uint64_t PDE;
typedef PDE*     PT;
typedef PT*      PD;
typedef PD*      PDPTR;

#define ENTRIES_PER_LEVEL 512
#define PAGE_SIZE 4096

// Flags
#define FLAG_PRESENT 0x001
#define FLAG_RW      0x002
#define FLAG_USER    0x004
#define FLAG_EXEC    0x008
#define FLAG_COW     0x010

// Get indexing bits..
#define LEVEL1_INDEX(va) ((va >> 30) & 0x1FF)
#define LEVEL2_INDEX(va) ((va >> 21) & 0x1FF)
#define LEVEL3_INDEX(va) ((va >> 12) & 0x1FF)
#define PAGE_OFFSET(va)  (va & 0xFFF)

// Kernel base address.
#define KERNEL_BASE 0xC0000000

// Track physical frames..
uint64_t refcount[1 << 20] = {0};
uint64_t physical_page_counter = 0;

// Allocate physical pages
uint64_t allocate_physical_page() {
    uint64_t addr = 0x100000 + physical_page_counter * PAGE_SIZE;
    refcount[physical_page_counter]++;
    physical_page_counter++;
    return addr;
}

uint64_t pa_index(uint64_t pa) {
    return (pa - 0x100000) / PAGE_SIZE;
}

PT create_page_table() {
    return calloc(ENTRIES_PER_LEVEL, sizeof(PDE)); }

PD create_page_directory() {
    return calloc(ENTRIES_PER_LEVEL, sizeof(PT));
}

PDPTR create_page_directory_pointer() {
    return calloc(ENTRIES_PER_LEVEL, sizeof(PD));
}

// Create a mapping.
void map_page(PDPTR pdptr, uint64_t va, uint64_t pa, uint64_t flags) {
    uint64_t l1 = LEVEL1_INDEX(va);
    uint64_t l2 = LEVEL2_INDEX(va);
    uint64_t l3 = LEVEL3_INDEX(va);

    if (!pdptr[l1]) pdptr[l1] = create_page_directory();
    if (!pdptr[l1][l2]) pdptr[l1][l2] = create_page_table();

    pdptr[l1][l2][l3] = (pa & ~0xFFF) | (flags | FLAG_PRESENT);
    refcount[pa_index(pa)]++;
}

void map_kernel_space(PDPTR pdptr) {
    for (uint64_t va = KERNEL_BASE; va < KERNEL_BASE + (PAGE_SIZE * 4); va += PAGE_SIZE) {
        uint64_t pa = allocate_physical_page();
        map_page(pdptr, va, pa, FLAG_RW | FLAG_EXEC); // Kernel only
    }
}


// Fork process.. Copy kernel pages..
PDPTR fork_process(PDPTR parent) {
    PDPTR child = create_page_directory_pointer();

    for (int l1 = 0; l1 < ENTRIES_PER_LEVEL; l1++) {
        if (!parent[l1]) continue;
        child[l1] = create_page_directory();

        for (int l2 = 0; l2 < ENTRIES_PER_LEVEL; l2++) {
            if (!parent[l1][l2]) continue;
            child[l1][l2] = create_page_table();

            for (int l3 = 0; l3 < ENTRIES_PER_LEVEL; l3++) {
                PDE pde = parent[l1][l2][l3];
                if (!(pde & FLAG_PRESENT)) continue;

                uint64_t pa = pde & ~0xFFF;
                uint64_t flags = pde & 0xFFF;

                if (flags & FLAG_USER) {
                    flags &= ~FLAG_RW;
                    flags |= FLAG_COW;
                    parent[l1][l2][l3] = (pa | flags);
                    child[l1][l2][l3]  = (pa | flags);
                    refcount[pa_index(pa)]++;
                } else {
                    child[l1][l2][l3] = pde; // shared kernel
                }
            }
        }
    }

    return child;
}

uint64_t handle_write_fault(PDPTR pt, uint64_t va, PDE pde) {
    uint64_t pa = pde & ~0xFFF;
    uint64_t flags = pde & 0xFFF;
    size_t index = pa_index(pa);

    if (refcount[index] > 1) {
        uint64_t new_pa = allocate_physical_page();
        refcount[index]--;
        flags = (flags | FLAG_RW) & ~FLAG_COW;

        uint64_t l1 = LEVEL1_INDEX(va);
        uint64_t l2 = LEVEL2_INDEX(va);
        uint64_t l3 = LEVEL3_INDEX(va);

        pt[l1][l2][l3] = (new_pa | flags);
        printf("COW: Created new PA 0x%" PRIx64 " for VA 0x%" PRIx64 "\n", new_pa, va);
        return new_pa;
    } else {
        uint64_t l1 = LEVEL1_INDEX(va);
        uint64_t l2 = LEVEL2_INDEX(va);
        uint64_t l3 = LEVEL3_INDEX(va);

        pt[l1][l2][l3] = (pa | ((flags | FLAG_RW) & ~FLAG_COW));
        printf("COW: Upgraded existing mapping to RW at VA 0x%" PRIx64 "\n", va);
        return pa;
    }
}

uint64_t translate(PDPTR pdptr, uint64_t va, const char* access) {
    uint64_t l1 = LEVEL1_INDEX(va);
    uint64_t l2 = LEVEL2_INDEX(va);
    uint64_t l3 = LEVEL3_INDEX(va);
    uint64_t offset = PAGE_OFFSET(va);

    PD pd_l2 = pdptr[l1];
    if (!pd_l2) {
        printf("Invalid L1 entry.\n");
        return 0;
    }

    PT pt = pd_l2[l2];
    if (!pt) {
        printf("Invalid L2 entry.\n");
        return 0;
    }

    PDE pde = pt[l3];
    if (!(pde & FLAG_PRESENT)) {
        printf("Page Fault: Not Present\n");
        return 0;
    }

    if (strcmp(access, "write") == 0) {
        if (pde & FLAG_COW) {
            return handle_write_fault(pdptr, va, pde) + offset;
        } else if (!(pde & FLAG_RW)) {
            printf("Page Fault: Write Access Violation\n");
            return 0;
        }
    }

    if (strcmp(access, "exec") == 0 && !(pde & FLAG_EXEC)) {
        printf("Page Fault: Execute Access Violation\n");
        return 0;
    }

    return (pde & ~0xFFF) + offset;
}

// Dump page tables.
void dump_page_table(PDPTR pt, const char* label) {
    printf("\n[%s Page Table Dump]\n", label);
    for (int l1 = 0; l1 < ENTRIES_PER_LEVEL; l1++) {
        if (!pt[l1]) continue;
        for (int l2 = 0; l2 < ENTRIES_PER_LEVEL; l2++) {
            if (!pt[l1][l2]) continue;
            for (int l3 = 0; l3 < ENTRIES_PER_LEVEL; l3++) {
                PDE pde = pt[l1][l2][l3];
                if (!(pde & FLAG_PRESENT)) continue;

                uint64_t va = ((uint64_t)l1 << 30) | ((uint64_t)l2 << 21) | ((uint64_t)l3 << 12);
                uint64_t pa = pde & ~0xFFF;
                uint64_t flags = pde & 0xFFF;

                printf("VA 0x%012" PRIx64 " -> PA 0x%012" PRIx64 " Flags:", va, pa);
                if (flags & FLAG_RW)   printf(" RW");
                if (flags & FLAG_USER) printf(" USER");
                if (flags & FLAG_EXEC) printf(" EXEC");
                if (flags & FLAG_COW)  printf(" COW");
                printf("\n");
            }
        }
    }
}

int main(void) {
    PDPTR procA = create_page_directory_pointer();
    map_kernel_space(procA); // Map kernel memory

    uint64_t user_va = 0x00400000;
    uint64_t user_pa = allocate_physical_page();
    map_page(procA, user_va, user_pa, FLAG_RW | FLAG_USER);

    PDPTR procB = fork_process(procA);

    printf("procB accessing kernel VA 0xC0000000: %s\n",
        translate(procB, 0xC0000000, "exec") ? "OK" : "FAULT");

    printf("procB write to user VA 0x%" PRIx64 ": ", user_va);
    uint64_t result = translate(procB, user_va, "write");
    if (result) printf("PA: 0x%" PRIx64 "\n", result);

    dump_page_table(procA, "procA");
    dump_page_table(procB, "procB");
    return 0;
}
