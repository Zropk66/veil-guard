/* MinGW 侧直发桩。
 *
 * GCC 的 x86-64 内联汇编无法表达第六个参数：syscall 要求 rcx 存放返回
 * 地址，第一个系统调用参数只能走 r10，第五个参数必须落在栈上的固定
 * 偏移，而这一位置由 GCC 而非本代码决定。因此改用独立汇编单元。
 *
 * 入参按 Windows x64 约定：rcx=SSN, rdx=a1, r8=a2, r9=a3,
 * [rsp+28h]=a4, [rsp+30h]=a5。
 */

    .text
    .intel_syntax noprefix
    .globl veil_syscall_stub
veil_syscall_stub:
    mov     rax, rcx            /* SSN */
    mov     r10, rdx            /* a1 */
    mov     rdx, r8             /* a2 */
    mov     r8,  r9             /* a3 */
    mov     r9,  [rsp + 28h]    /* a4 */
    mov     r11, [rsp + 30h]    /* a5 */
    mov     [rsp + 28h], r11
    syscall
    ret
