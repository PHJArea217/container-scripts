#include <linux/filter.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include "arch/current/arch-functions.h"
struct ctrtool_arraylist {
	void *start;
	size_t elem_size;
	size_t nr;
	size_t max;
};
struct ctrtool_rlimit {
	int limit_name;
	unsigned change_soft:1;
	unsigned change_hard:1;
	struct rlimit limit_value;
};
void ctrtool_cheap_perror(const char *str, int errno_);
int cl_nsenter_params(const char *param, int *errno_ptr, int is_pre);
int ctrtool_install_seccomp_from_fd(int fd, struct sock_fprog *result);
int ctrtool_close_range(int min_fd, int max_fd, unsigned int flags);
int ctrtool_close_range_compat(int min_fd, int max_fd, unsigned int flags);
void ctrtool_mini_init_set_fds(int *fds, size_t num_fds);
void ctrtool_mini_init_set_listen_pid_fds(int nr_fds);
char *ctrtool_strdup(const char *str);
long ctrtool_syscall_errno_i(long nr, int *errno_ptr, long a, long b, long c, long d, long e, long f);
#define ctrtool_syscall_errno(nr, ptr, a, b, c, d, e, f) ctrtool_syscall_errno_i(nr, ptr, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))
int ctrtool_arraylist_expand(struct ctrtool_arraylist *list, const void *new_element, size_t step);
int ctrtool_arraylist_expand_s(struct ctrtool_arraylist *list, const void *new_element, size_t step, void **result);
int ctrtool_load_permitted_caps(void);
int ctrtool_parse_int_array(const char *input_str, struct iovec *result, unsigned int i_size);
int ctrtool_parse_rlimit(const char *spec, struct ctrtool_rlimit *result);
int ctrtool_escape(void);
int ctrtool_save_argv(int argc, char **argv);
void ctrtool_clear_saved_argv(void);
int ctrtool_prepare_caps_for_exec(int *errno_ptr);
