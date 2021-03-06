#include <linux/filter.h>
#include <sys/types.h>
#include "arch/current/arch-functions.h"
struct ctrtool_arraylist {
	void *start;
	size_t elem_size;
	size_t nr;
	size_t max;
};
void ctrtool_cheap_perror(const char *str, int errno_);
int cl_nsenter_params(const char *param, int *errno_ptr);
int ctrtool_install_seccomp_from_fd(int fd, struct sock_fprog *result);
int ctrtool_close_range(int min_fd, int max_fd, unsigned int flags);
void ctrtool_mini_init_set_fds(int *fds, size_t num_fds);
void ctrtool_mini_init_set_listen_pid_fds(int nr_fds);
char *ctrtool_strdup(const char *str);
long ctrtool_syscall_errno_i(long nr, int *errno_ptr, long a, long b, long c, long d, long e, long f);
#define ctrtool_syscall_errno(nr, ptr, a, b, c, d, e, f) ctrtool_syscall_errno_i(nr, ptr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))
int ctrtool_arraylist_expand(struct ctrtool_arraylist *list, const void *new_element, size_t step);
