.globl ctrtool_arch_x86_64_syscall_r, ctrtool_arch_x86_64_exit
.align 16
ctrtool_arch_x86_64_syscall_r:
	endbr64
	mov %rcx, %r10
	mov 8(%rsp), %rax
	syscall
	ret
.align 16
ctrtool_arch_x86_64_exit:
	endbr64
	xor %rax, %rax
	mov $60, %al
	syscall
x:	hlt
	jmp x

.section .note.GNU-stack
