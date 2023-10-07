#include <syscall.h>
#define CTRTOOL_IS_ARCH_GENERIC
long ctrtool_arch_generic_syscall(long nr, long a, long b, long c, long d, long e, long f);
__attribute__((noreturn)) void ctrtool_arch_generic_exit(int status);
#define CTRTOOL_SYS_pidfd_open __NR_pidfd_open
#define CTRTOOL_SYS_close_range __NR_close_range
#define CTRTOOL_SYS_pidfd_getfd __NR_pidfd_getfd
#define CTRTOOL_SYS_openat2 __NR_openat2
#define ctrtool_syscall(nr, a, b, c, d, e, f) ctrtool_arch_generic_syscall(nr, (long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f))
#define ctrtool_raw_syscall(nr, a, b, c, d, e, f) ctrtool_arch_generic_syscall(nr, (long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f))
long ctrtool_clone_onearg(unsigned long arg);
#define ctrtool_exit(arg) ctrtool_arch_generic_exit(arg)
