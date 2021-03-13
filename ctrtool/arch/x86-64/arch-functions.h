long ctrtool_arch_x86_64_syscall_r(long a, long b, long c, long d, long e, long f, long nr);
__attribute__((noreturn)) void ctrtool_arch_x86_64_exit(int status);
#define CTRTOOL_SYS_pidfd_open 434
#define CTRTOOL_SYS_pidfd_getfd 438
#define ctrtool_syscall(nr, a, b, c, d, e, f) ctrtool_arch_x86_64_syscall_r((long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f), nr)
#define ctrtool_raw_syscall(nr, a, b, c, d, e, f) ctrtool_arch_x86_64_syscall_r((long) (a), (long) (b), (long) (c), (long) (d), (long) (e), (long) (f), nr)
#define ctrtool_clone_onearg(arg) ctrtool_syscall(56, arg, 0, 0, 0, 0, 0)
#define ctrtool_exit(arg) ctrtool_arch_x86_64_exit(arg)
