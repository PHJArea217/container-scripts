#include <linux/filter.h>
#include <sys/types.h>
void ctrtool_cheap_perror(const char *str, int errno_);
int cl_nsenter_params(const char *param);
int ctrtool_install_seccomp_from_fd(int fd, struct sock_fprog *result);
int ctrtool_close_range(int min_fd, int max_fd, unsigned int flags);
void ctrtool_mini_init_set_fds(int *fds, size_t num_fds);
void ctrtool_mini_init_set_listen_pid_fds(int nr_fds);
