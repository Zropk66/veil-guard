/* MinGW 侧直发桩。
 *
 * GCC 的 x86-64 内联汇编无法表达第六个系统调用参数：syscall 要求 rcx
 * 存放返回地址，第一个参数只能走 r10，第五、第六个参数必须落在栈上
 * 由调用方预留的位置，而这一位置由 GCC 而非本代码决定。因此改用独立
 * 汇编单元。
 *
 * 入参按 Windows x64 约定：rcx=SSN, rdx=a1, r8=a2, r9=a3,
 * [rsp+0x28]=a4, [rsp+0x30]=a5, [rsp+0x38]=a6。
 * 系统调用侧：r10=a1, rdx=a2, r8=a3, r9=a4, [rsp+0x28]=a5, [rsp+0x30]=a6。
 */

    .text
    .intel_syntax noprefix
    .globl veil_syscall_stub
veil_syscall_stub:
    mov     rax, rcx
    mov     r10, rdx
    mov     rdx, r8
    mov     r8, r9
    mov     r9, QWORD PTR [rsp+0x28]
    mov     r11, QWORD PTR [rsp+0x30]
    mov     QWORD PTR [rsp+0x28], r11
    mov     r11, QWORD PTR [rsp+0x38]
    mov     QWORD PTR [rsp+0x30], r11
    syscall
    ret
