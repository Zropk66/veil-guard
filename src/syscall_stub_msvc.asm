; MSVC x64 不允许内联汇编，直发路径由此桩提供。
;
; 入参按 Windows x64 约定：rcx=SSN, rdx=a1, r8=a2, r9=a3,
; [rsp+28h]=a4, [rsp+30h]=a5。
; syscall 指令要求 rcx 存放返回地址，故第一个系统调用参数改由 r10 传递。

.code
veil_syscall_stub PROC
    mov     rax, rcx            ; SSN
    mov     r10, rdx            ; a1
    mov     rdx, r8             ; a2
    mov     r8,  r9             ; a3
    mov     r9,  [rsp + 28h]    ; a4
    mov     r11, [rsp + 30h]    ; a5
    mov     [rsp + 28h], r11
    syscall
    ret
veil_syscall_stub ENDP

END
