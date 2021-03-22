.syntax unified

.globl ctrtool_arch_armhf_syscall_r, ctrtool_arch_armhf_exit

.ifdef CTRTOOL_ASM_TEST
# Call sync(), then exit with status 242. Somehow appears to crash if running in thumb mode.
test:
	mov r3, #36
	push {r0, r1, r2, r3}
	bl ctrtool_arch_armhf_syscall_r
	mov r0, #242
	bl ctrtool_arch_armhf_exit
.endif

# The following code should compile in both arm and thumb modes. When compiling as part of ctrtool,
# it should match the mode of the C code (thumb by default); otherwise, it may crash.

ctrtool_arch_armhf_exit:
	mov r7, #1
	swi 0
x:
	wfi
	b x

# First seven arguments are the syscall parameters; the system call number is in the eighth argument.
ctrtool_arch_armhf_syscall_r:
	push {r4, r5, r6, r7}
	ldr r4, [sp, #16]
	ldr r5, [sp, #20]
	ldr r6, [sp, #24]
	ldr r7, [sp, #28]
	swi 0
	pop {r4, r5, r6, r7}
	bx lr

.section .note.GNU-stack
