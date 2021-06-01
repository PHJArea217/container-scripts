long ctrtool_arch_x86_32_syscall(long nr, long a, long b, long c, long d, long e, long f);
long ctrtool_arch_x86_32_syscall_int_0x80(long nr, long a, long b, long c, long d, long e, long f);
long ctrtool_arch_x86_32_clone_onearg(long flags);
__attribute__((noreturn)) void ctrtool_arch_x86_32_exit(int status);
#define ctrtool_syscall(nr, a, b, c, d, e, f) ctrtool_arch_x86_32_syscall(nr, \
		(long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))
#define ctrtool_raw_syscall(nr, a, b, c, d, e, f) ctrtool_arch_x86_32_syscall_int_0x80(nr, \
		(long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))
#define ctrtool_clone_onearg(flags) ctrtool_arch_x86_32_clone_onearg(flags)
#define ctrtool_exit(s) ctrtool_arch_x86_32_exit(s)

#define CTRTOOL_SYS_pidfd_open 434
#define CTRTOOL_SYS_close_range 436
#define CTRTOOL_SYS_openat2 437
#define CTRTOOL_SYS_pidfd_getfd 438
