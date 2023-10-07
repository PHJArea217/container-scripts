#define _GNU_SOURCE
#include <unistd.h>
#include <syscall.h>
#include <stdint.h>
#include <errno.h>
long ctrtool_arch_generic_syscall(long nr, long a, long b, long c, long d, long e, long f) {
	int saved_errno = errno;
	errno = 0;
	long ret_val = syscall(nr, a, b, c, d, e, f);
	if (ret_val == -1) {
		ret_val = -errno;
	}
	errno = saved_errno;
	return ret_val;
}
long ctrtool_clone_onearg(unsigned long arg) {
	uint64_t clone_args[8] = {0};
	clone_args[0] = arg & -256L; /* flags */
	clone_args[4] = arg & 255; /* exit_signal */
	return ctrtool_arch_generic_syscall(__NR_clone3, (long) clone_args, sizeof(clone_args), 0, 0, 0, 0);
}
__attribute__((noreturn)) void ctrtool_arch_generic_exit(int status) {
	syscall(SYS_exit_group, status, 0, 0, 0, 0, 0);
	while (1) ;
}
