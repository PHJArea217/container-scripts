long ctrtool_arch_armhf_syscall_r(long a, long b, long c, long d, long e, long f, long g, long nr);
__attribute__((noreturn)) void ctrtool_arch_armhf_exit(int status);
#define CTRTOOL_SYS_pidfd_open 434
#define CTRTOOL_SYS_close_range 436
#define CTRTOOL_SYS_openat2 437
#define CTRTOOL_SYS_pidfd_getfd 438
#define ctrtool_syscall(nr, a, b, c, d, e, f) ctrtool_arch_armhf_syscall_r((long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f), 0, nr)
#define ctrtool_raw_syscall(nr, a, b, c, d, e, f) ctrtool_arch_armhf_syscall_r((long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f), 0, nr)
#define ctrtool_clone_onearg(arg) ctrtool_syscall(120, arg, 0, 0, 0, 0, 0)
#define ctrtool_exit(arg) ctrtool_arch_armhf_exit(arg)
