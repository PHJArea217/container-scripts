#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/uio.h>
#include <syscall.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
static int int32_to_num(uint32_t num, char *result) {
	static char digits[] = "0123456789";
	result[9] = digits[num % 10];
	num /= 10;
	result[8] = digits[num % 10];
	num /= 10;
	result[7] = digits[num % 10];
	num /= 10;
	result[6] = digits[num % 10];
	num /= 10;
	result[5] = digits[num % 10];
	num /= 10;
	result[4] = digits[num % 10];
	num /= 10;
	result[3] = digits[num % 10];
	num /= 10;
	result[2] = digits[num % 10];
	num /= 10;
	result[1] = digits[num % 10];
	num /= 10;
	result[0] = digits[num % 10];
	for (int i = 0; i < 9; i++) {
		if (result[i] > '0') return i;
	}
	return 9;
}
void ctrtool_cheap_perror(const char *str, int errno_) {
	size_t l = 0;
	const char *s = str;
	while (*s) {
		l++;
		s++;
	}
	char b[10];
	int32_to_num(errno_, b);
	struct iovec iov[] = {
		{(void *) str, l},
		{": errno ", 8},
		{b, 10},
		{"\n", 1}
	};
	ctrtool_syscall(SYS_writev, STDERR_FILENO, iov, 4, 0, 0, 0);
}
int ctrtool_install_seccomp_from_fd(int fd, struct sock_fprog *result) {
	size_t buffer_size = 0; /* in bytes*/
	const static size_t max_size = (BPF_MAXINSNS + 1) * sizeof(struct sock_filter);
	char *buffer = calloc(BPF_MAXINSNS + 1, sizeof(struct sock_filter));
	if (buffer == NULL) return -1;
	while (1) {
		ssize_t nread = read(fd, buffer + buffer_size, max_size - buffer_size);
		if (nread < 0) {
			free(buffer);
			return -1;
		}
		if (nread == 0) {
			break;
		}
		buffer_size += nread;
		if (buffer_size >= max_size) {
			free(buffer);
			errno = ENOSPC;
			return -1;
		}
	}
	size_t seccomp_size = buffer_size / sizeof(struct sock_filter);
	if ((seccomp_size * sizeof(struct sock_filter)) != buffer_size) {
		free(buffer);
		errno = EINVAL;
		return -1;
	}
	result->len = seccomp_size;
	result->filter = (struct sock_filter *) buffer;
	return 0;
}
int ctrtool_close_range_compat(int min_fd, int max_fd, unsigned int flags) {
	if (flags) {
		errno = EINVAL;
		return -1;
	}
	struct ctrtool_arraylist fd_list = {0};
	fd_list.elem_size = sizeof(int);
	DIR *proc_pid_dir = opendir("/proc/self/fd");
	if (proc_pid_dir == NULL) {
		return -1;
	}
	while (1) {
		errno = 0;
		struct dirent *e = readdir(proc_pid_dir);
		if (!e) break;
		if (isdigit(e->d_name[0])) {
			int fd_number = atoi(e->d_name);
			if ((fd_number >= min_fd) && (fd_number <= max_fd)) {
				if (ctrtool_arraylist_expand(&fd_list, &fd_number, 10)) {
					errno = ENOMEM;
					break;
				}
			}
		}
	}
	if (errno) {
		if (closedir(proc_pid_dir)) {
			abort();
		}
		free(fd_list.start);
		return -1;
	}
	if (closedir(proc_pid_dir)) {
		abort();
	}
	int *fd_list_i = fd_list.start;
	for (size_t i = 0; i < fd_list.nr; i++) {
		close(fd_list_i[i]);
	}
	free(fd_list.start);
	errno = 0;
	return 0;
}
int ctrtool_close_range(int min_fd, int max_fd, unsigned int flags) {
	if (min_fd < 0) {
		errno = EINVAL;
		return -1;
	}
	if (max_fd < 0) {
		errno = EINVAL;
		return -1;
	}
	int rv = -1;
	errno = ENOSYS;
#ifdef CTRTOOL_SYS_close_range
	rv = syscall(CTRTOOL_SYS_close_range, min_fd, max_fd, flags, 0, 0, 0);
#endif
	if ((rv < 0) && (errno == ENOSYS)) {
		return ctrtool_close_range_compat(min_fd, max_fd, flags);
	}
	return rv;
}
/* TODO: Maybe make the "3" customizable? */
void ctrtool_mini_init_set_fds(int *fds, size_t num_fds) {
	if (num_fds > INT_MAX - 3) {
		abort();
	}
	int min_fd = 3 + num_fds;
	for (size_t i = 0; i < num_fds; i++) {
		if (fds[i] >= 3 && fds[i] < min_fd) {
			int new_fd = fcntl(fds[i], F_DUPFD_CLOEXEC, min_fd);
			if (new_fd < min_fd) {
				_exit(127);
			}
			if (fds[i] >= 3) close(fds[i]);
			fds[i] = new_fd;
		}
	}
	for (size_t i = 0; i < num_fds; i++) {
		if (dup2(fds[i], 3 + i) < 0) {
			_exit(127);
		}
		if (fds[i] >= 3) close(fds[i]);
		fds[i] = 3 + i;
	}
	int close_range_return = ctrtool_close_range(min_fd, INT_MAX, 0);
	if (close_range_return < 0) {
		_exit(127);
	}
}
void ctrtool_mini_init_set_listen_pid_fds(int nr_fds) {
	char value_buf[12];
	memset(value_buf, 0, 12);
	pid_t current_pid = getpid();
	if (current_pid <= 0) _exit(127);
	int p = int32_to_num(current_pid, value_buf);
	if (setenv("LISTEN_PID", &value_buf[p], 1)) _exit(127);

	memset(value_buf, 0, 12);
	p = int32_to_num(nr_fds, value_buf);
	if (setenv("LISTEN_FDS", &value_buf[p], 1)) _exit(127);
}
char *ctrtool_strdup(const char *str) {
	char *r = strdup(str);
	if (!r) {
//		exit(255);
		abort();
	}
	return r;
}
long ctrtool_syscall_errno_i(long nr, int *errno_ptr, long a, long b, long c, long d, long e, long f) {
	unsigned long return_value = ctrtool_syscall(nr, a, b, c, d, e, f);
	if (return_value > -4096UL) {
		*errno_ptr = -return_value;
		return -1;
	}
	return return_value;
}
int ctrtool_arraylist_expand_s(struct ctrtool_arraylist *list, const void *new_element, size_t step, void **result) {
	if (list->elem_size == 0) {
		return -1;
	}
	if (step <= 0) {
		return -1;
	}
	size_t new_list_size = list->nr + 1;
	if (new_list_size > list->max) {
		size_t new_list_max = list->max + step;
		void *new_list_head = reallocarray(list->start, list->elem_size, new_list_max);
		if (new_list_head == NULL) return -1;
		list->start = new_list_head;
		list->max = new_list_max;
	}
	void *new_location = &((char *) list->start)[list->nr * list->elem_size];
	if (new_element) {
		memcpy(new_location, new_element, list->elem_size);
	} else {
		memset(new_location, 0, list->elem_size);
	}
	if (result) {
		*result = new_location;
	}
	list->nr = new_list_size;
	return 0;
}
int ctrtool_arraylist_expand(struct ctrtool_arraylist *list, const void *new_element, size_t step) {
	return ctrtool_arraylist_expand_s(list, new_element, step, NULL);
}
int ctrtool_load_permitted_caps(void) {
	struct __user_cap_header_struct cap_h = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct cap_d[2] = {0};

	long sys_retval = ctrtool_syscall(SYS_capget, &cap_h, cap_d, 0, 0, 0, 0);
	if (sys_retval) {
		errno = -sys_retval;
		return -1;
	}
	cap_d[0].effective = cap_d[0].permitted;
	cap_d[1].effective = cap_d[1].permitted;
	sys_retval = ctrtool_syscall(SYS_capset, &cap_h, cap_d, 0, 0, 0, 0);
	if (sys_retval) {
		errno = -sys_retval;
		return -1;
	}
	return 0;
}
int ctrtool_parse_int_array(const char *input_str, struct iovec *result, unsigned int i_size) {
	if (i_size > sizeof(unsigned long long)) {
		errno = EINVAL;
		return -1;
	}
	char *i_str_dup = strdup(input_str);
	if (i_str_dup == NULL) return -1;
	struct ctrtool_arraylist list = {0};
	list.elem_size = i_size;
	char *saveptr = NULL;
	for (char *s = strtok_r(i_str_dup, ",", &saveptr); s; s = strtok_r(NULL, ",", &saveptr)) {
		errno = 0;
		if (!isdigit(s[0])) {
			free(list.start);
			free(i_str_dup);
			return -1;
		}
		unsigned long long result_n = strtoull(s, NULL, 0);
		if (errno) {
			free(list.start);
			free(i_str_dup);
			return -1;
		}
		if (i_size < sizeof(unsigned long long)) {
			if (result_n >= (1ULL << (CHAR_BIT * i_size))) {
				free(list.start);
				free(i_str_dup);
				errno = ERANGE;
				return -1;
			}
		}
		char *_result = (char *) &result_n;
#if __BYTE_ORDER == __BIG_ENDIAN
		_result += sizeof(unsigned long long) - i_size;
#endif
		if (ctrtool_arraylist_expand(&list, _result, 10)) {
			free(list.start);
			free(i_str_dup);
			return -1;
		}
	}
	free(i_str_dup);
	result->iov_base = list.start;
	result->iov_len = list.nr;
	return 0;
}
static int ctrtool_parse_rlimit_string(const char *value, size_t limit, rlim_t *result) {
	if (limit > 40) {
		errno = ERANGE;
		return -1;
	}
	if ((limit == 0) || (value[0] == 0)) {
		return 1;
	}
	char *s_d = strndupa(value, limit);
	if (strcasecmp(s_d, "unlimited") == 0) {
		*result = RLIM_INFINITY;
		return 0;
	}
	if (!isdigit(s_d[0])) {
		errno = EINVAL;
		return -1;
	}
	errno = 0;
	unsigned long long limit_val = strtoull(s_d, NULL, 0);
	if (errno) {
		errno = ERANGE;
		return -1;
	}
	if (sizeof(rlim_t) < sizeof(unsigned long long)) {
		if (limit_val >= (1ULL << (sizeof(rlim_t) * CHAR_BIT))) {
			errno = ERANGE;
			return -1;
		}
	}
	*result = limit_val;
	return 0;
}
struct ctrtool_rlimit_spec {
	const char *name;
	int value;
};
static const struct ctrtool_rlimit_spec rlimits[] = {
	{"as", RLIMIT_AS},
	{"c", RLIMIT_CORE},
	{"core", RLIMIT_CORE},
	{"cpu", RLIMIT_CPU},
	{"d", RLIMIT_DATA},
	{"data", RLIMIT_DATA},
	{"e", RLIMIT_NICE},
	{"f", RLIMIT_FSIZE},
	{"fsize", RLIMIT_FSIZE},
	{"i", RLIMIT_SIGPENDING},
	{"l", RLIMIT_MEMLOCK},
	{"locks", RLIMIT_LOCKS},
	{"m", RLIMIT_RSS},
	{"memlock", RLIMIT_MEMLOCK},
	{"msgqueue", RLIMIT_MSGQUEUE},
	{"n", RLIMIT_NOFILE},
	{"nice", RLIMIT_NICE},
	{"nofile", RLIMIT_NOFILE},
	{"nproc", RLIMIT_NPROC},
	{"q", RLIMIT_MSGQUEUE},
	{"r", RLIMIT_RTPRIO},
	{"rss", RLIMIT_RSS},
	{"rtprio", RLIMIT_RTPRIO},
	{"rttime", RLIMIT_RTTIME},
	{"s", RLIMIT_STACK},
	{"sigpending", RLIMIT_SIGPENDING},
	{"stack", RLIMIT_STACK},
	{"t", RLIMIT_CPU},
	{"u", RLIMIT_NPROC},
	{"v", RLIMIT_AS},
	{"x", RLIMIT_LOCKS},
	{"y", RLIMIT_RTTIME}
};
static int compare_rlimits(const void *a_p, const void *b_p) {
	const struct ctrtool_rlimit_spec *a = a_p;
	const struct ctrtool_rlimit_spec *b = b_p;
	return strcasecmp(a->name, b->name);
}
int ctrtool_parse_rlimit(const char *spec, struct ctrtool_rlimit *result) {
	char *equal_brk = strchr(spec, '=');
	if (!equal_brk) {
		errno = EINVAL;
		return -1;
	}
	size_t s_limit = equal_brk - spec;
	if (s_limit > 20) s_limit = 20;
	char *spec_s = strndupa(spec, s_limit);
	struct ctrtool_rlimit_spec m_spec = {spec_s, 0};
	struct ctrtool_rlimit_spec *rlimit_result = bsearch(&m_spec, rlimits, sizeof(rlimits)/sizeof(rlimits[0]), sizeof(rlimits[0]), compare_rlimits);
	if (!rlimit_result) {
		errno = ENOENT;
		return -1;
	}
	equal_brk += 1;
	char *colon_brk = strchr(equal_brk, ':');
	if (!colon_brk) {
		rlim_t f_result = -1;
		if (ctrtool_parse_rlimit_string(equal_brk, 40, &f_result)) {
			errno = EINVAL;
			return -1;
		}
		result->change_hard = 1;
		result->change_soft = 1;
		result->limit_name = rlimit_result->value;
		result->limit_value.rlim_cur = f_result;
		result->limit_value.rlim_max = f_result;
	} else {
		rlim_t f_result_soft = -1;
		rlim_t f_result_hard = -1;
		int r_1 = ctrtool_parse_rlimit_string(equal_brk, colon_brk - equal_brk, &f_result_soft);
		if (r_1 < 0) {
			errno = EINVAL;
			return -1;
		}
		int r_2 = ctrtool_parse_rlimit_string(&colon_brk[1], 40, &f_result_hard);
		if (r_2 < 0) {
			errno = EINVAL;
			return -1;
		}
		if (r_1 == 0) {
			result->change_soft = 1;
			result->limit_value.rlim_cur = f_result_soft;
		}
		if (r_2 == 0) {
			result->change_hard = 1;
			result->limit_value.rlim_max = f_result_hard;
		}
		result->limit_name = rlimit_result->value;
	}
	return 0;
}
char **ctrtool_saved_argv = NULL;
static int ctrtool_already_escaped = 0;
int ctrtool_save_argv(int argc, char **argv) {
	char **new_argv = calloc(sizeof(char *), argc+1);
	if (new_argv == NULL) return -1;
	for (int i = 0; i < argc; i++) {
		const char *old_p = argv[i];
		if (!old_p) {
			free(new_argv);
			return -1;
		}
		char *new_p = strdup(old_p);
		if (!new_p) {
			free(new_argv);
			return -1;
		}
		new_argv[i] = new_p;
	}
	ctrtool_saved_argv = new_argv;
	return 0;
}
int ctrtool_escape(void) {
	if (ctrtool_already_escaped) return 0;
	if (!ctrtool_saved_argv) {
		return -1;
	}
	int exe_fd = open("/proc/self/exe", O_RDONLY|O_NOCTTY|O_CLOEXEC);
	if (exe_fd < 0) {
		return -1;
	}
	int memfd_fd = memfd_create("ctrtool", MFD_CLOEXEC|MFD_ALLOW_SEALING);
	if (memfd_fd < 0) {
		close(exe_fd);
		return -1;
	}
	if (fchmod(memfd_fd, 0555)) {
		goto close_fail;
	}
	struct stat st_exe = {0};
	struct stat st_memfd = {0};
	if (fstat(exe_fd, &st_exe)) goto close_fail;
	if (fstat(memfd_fd, &st_memfd)) goto close_fail;
	if (st_exe.st_dev == st_memfd.st_dev) {
		int f_seals = fcntl(exe_fd, F_GET_SEALS, 0);
		if (f_seals < 0) goto close_fail;
		if ((f_seals & (F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK)) == (F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK)) {
			close(memfd_fd);
			close(exe_fd);
			char **c_ptr = ctrtool_saved_argv;
			while (*c_ptr) {
				free(*c_ptr);
				c_ptr++;
			}
			free(ctrtool_saved_argv);
			ctrtool_saved_argv = NULL;
			ctrtool_already_escaped = 1;
			return 0;
		}
	}
	while (1) {
		ssize_t sf_result = sendfile(memfd_fd, exe_fd, NULL, 1048576);
		if (sf_result < 0) {
			goto close_fail;
		}
		if (sf_result == 0) {
			break;
		}
	}
	if (fcntl(memfd_fd, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK)) {
		goto close_fail;
	}
	ctrtool_syscall(SYS_execveat, memfd_fd, "", ctrtool_saved_argv, environ, AT_EMPTY_PATH, 0);
close_fail:
	close(exe_fd);
	close(memfd_fd);
	return -1;
}
