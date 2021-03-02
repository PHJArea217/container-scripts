#include <linux/filter.h>
void ctrtool_cheap_perror(const char *str, int errno_);
int cl_nsenter_params(const char *param);
int ctrtool_install_seccomp_from_fd(int fd, struct sock_fprog *result);
