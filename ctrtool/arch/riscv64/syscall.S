.globl ctrtool_arch_riscv64_syscall_r, ctrtool_arch_riscv64_exit
ctrtool_arch_riscv64_syscall_r:
	mv a7, a6
	ecall
	ret
ctrtool_arch_riscv64_exit:
	li a7, 94
	ecall
x:
	j x

.section .note.GNU-stack
