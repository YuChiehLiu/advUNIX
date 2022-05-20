%define ISLONGJMPCALL 777

; system call marco
%macro gensys 2
        global sys_%2:function
sys_%2:
        push    r10
        mov     r10, rcx
        mov     rax, %1
        syscall
        pop     r10
        ret
%endmacro

        gensys   1, write
        gensys  13, rt_sigaction
        gensys  14, rt_sigprocmask
        gensys  34, pause
        gensys  35, nanosleep
        gensys  37, alarm
        gensys  60, exit
        gensys 127, rt_sigpending

; function implemented with ASM
        global __myrt:function
        global setjmp:function
        global longjmp:function
__myrt:
        mov rax, 15
        syscall

setjmp:
        pop rcx
        mov [rdi+0x00], rcx
        mov [rdi+0x08], rbx
        mov [rdi+0x10], rsp
        mov [rdi+0x18], rbp
        mov [rdi+0x20], r12
        mov [rdi+0x28], r13
        mov [rdi+0x30], r14
        mov [rdi+0x38], r15
        push rcx
        push rdi
        mov rdi, 2
        lea rsi, [rsp-8]
        mov QWORD [rsi], 0
        lea rdx, [rsp-16]
        mov rcx, 8
        call sys_rt_sigprocmask
        mov rax, [rsp-16]
        pop rdi
        mov [rdi+0x40], rax
        mov rax, 0
        ret

longjmp:
        push rsi
        push rdi
        lea rsi, [rdi+0x40]
        mov rdi, 2
        lea rdx, [rsp-16]
        mov rcx, 8
        call sys_rt_sigprocmask
        pop rdi
        pop rax
        mov rcx, [rdi+0x00]
        mov rbx, [rdi+0x08]
        mov rsp, [rdi+0x10]
        mov rbp, [rdi+0x18]
        mov r12, [rdi+0x20]
        mov r13, [rdi+0x28]
        mov r14, [rdi+0x30]
        mov r15, [rdi+0x38]
        jmp rcx

