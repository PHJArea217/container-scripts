.globl ctrtool_arch_x86_32_clone_onearg, ctrtool_arch_x86_32_syscall, ctrtool_arch_x86_32_syscall_int_0x80, ctrtool_arch_x86_32_exit
.align 8
ctrtool_arch_x86_32_exit:
	endbr32
	xor %eax, %eax
	mov $252, %al
	mov 4(%esp), %ebx
	int $0x80
x:
	hlt
	jmp x
.align 8
ctrtool_arch_x86_32_clone_onearg:
	endbr32
	push %ebx
	push %esi
	push %edi
	xor %eax, %eax
	mov $120, %al
	mov 16(%esp), %ebx
	xor %ecx, %ecx
	xor %edx, %edx
	xor %esi, %esi
	xor %edi, %edi
	int $0x80
	pop %edi
	pop %esi
	pop %ebx
	ret

.align 8
ctrtool_arch_x86_32_syscall:
	endbr32
	push %ebx
	push %esi
	push %edi
	push %ebp
	mov 20(%esp), %eax
	mov 24(%esp), %ebx
	mov 28(%esp), %ecx
	mov 32(%esp), %edx
	mov 36(%esp), %esi
	mov 40(%esp), %edi
	mov 44(%esp), %ebp
	call *%gs:0x10
	pop %ebp
	pop %edi
	pop %esi
	pop %ebx
	ret

.align 8
ctrtool_arch_x86_32_syscall_int_0x80:
	endbr32
	push %ebx
	push %esi
	push %edi
	push %ebp
	mov 20(%esp), %eax
	mov 24(%esp), %ebx
	mov 28(%esp), %ecx
	mov 32(%esp), %edx
	mov 36(%esp), %esi
	mov 40(%esp), %edi
	mov 44(%esp), %ebp
	int $0x80
	pop %ebp
	pop %edi
	pop %esi
	pop %ebx
	ret

.section .note.GNU-stack
