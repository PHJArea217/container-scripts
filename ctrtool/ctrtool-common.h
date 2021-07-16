#include <linux/filter.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <sys/resource.h>
#include <stdlib.h>
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
int ctrtool_int32_to_num(uint32_t num, char *result);
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
int ctrtool_make_fd_nonblocking(int fd, int nonblock);
int ctrtool_make_fd_cloexec(int fd, int cloexec);
int ctrtool_export_fd(int fd, const char *env_name);
int ctrtool_read_fd_env_spec(const char *arg, int print_msg, int *result);
int ctrtool_unix_scm_send(int sock_fd, int fd);
int ctrtool_unix_scm_recv(int sock_fd);
struct ctrtool_timens_offset_setting {
	clockid_t clk_id;
	struct timespec clk_offset;
};
struct ctrtool_cred {
	uint32_t which;
	uint32_t flags;
	uint64_t effective_caps;
	uint64_t permitted_caps;
	uint64_t inheritable_caps;
	uint64_t bounding_caps;
	uint64_t ambient_caps;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t fsuid;
	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	gid_t fsgid;
	gid_t *supp_groups;
	uint32_t nr_supp_groups;
	struct ctrtool_timens_offset_setting *timens_offsets;
	uint32_t nr_timens_offsets;
	int userns_fd;
	int mntns_fd;
	int utsns_fd;
	int ipcns_fd;
	int netns_fd;
	int pidns_fd;
	int cgroupns_fd;
	int timens_fd;
};
#define CTRTOOL_CLOSE_NO_ERROR(fd) ctrtool_syscall(SYS_close, fd, 0, 0, 0, 0, 0)
#define ctrtool_assert(expr) do {if (expr) {} else {fprintf(stderr, "ctrtool_assert %s failed on %s:%d. Aborting.\n", #expr, __FILE__, __LINE__); abort();}} while (0)
