#include <syscall.h>
long ctrtool_arch_generic_syscall(long nr, long a, long b, long c, long d, long e, long f);
__attribute__((noreturn)) void ctrtool_arch_generic_exit(int status);
#define CTRTOOL_SYS_pidfd_open SYS_pidfd_open
#define CTRTOOL_SYS_pidfd_getfd SYS_pidfd_getfd
#define ctrtool_syscall(nr, a, b, c, d, e, f) ctrtool_arch_generic_syscall(nr, (long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f))
#define ctrtool_raw_syscall(nr, a, b, c, d, e, f) ctrtool_arch_generic_syscall(nr, (long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f))
#define ctrtool_clone_onearg(arg) ctrtool_syscall(SYS_clone, arg, 0, 0, 0, 0, 0)
#define ctrtool_exit(arg) ctrtool_arch_generic_exit(arg)
