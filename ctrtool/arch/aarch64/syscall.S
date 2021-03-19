.globl ctrtool_arch_aarch64_syscall_r, ctrtool_arch_aarch64_exit
ctrtool_arch_aarch64_syscall_r:
	mov x8, x6
	svc #0
	ret
ctrtool_arch_aarch64_exit:
	mov x8, #93
	svc #0
x:	wfi
	b x

.section .note.GNU-stack
