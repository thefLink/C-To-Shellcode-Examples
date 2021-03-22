; Based on http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html and https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
extern go
global alignstack

segment .text

alignstack:
    push rdi                    ; backup rdi since we will be using this as our main register
    mov rdi, rsp                ; save stack pointer to rdi
    and rsp, byte -0x10         ; align stack with 16 bytes
    sub rsp, byte +0x20         ; allocate some space for our C function
    call go                   ; call the C function
    mov rsp, rdi                ; restore stack pointer
    pop rdi                     ; restore rdi
    ret                         ; return where we left
