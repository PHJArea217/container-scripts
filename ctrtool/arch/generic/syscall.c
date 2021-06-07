#define _GNU_SOURCE
#include <unistd.h>
#include <syscall.h>
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
__attribute__((noreturn)) void ctrtool_arch_generic_exit(int status) {
	syscall(SYS_exit_group, status, 0, 0, 0, 0, 0);
	while (1) ;
}
