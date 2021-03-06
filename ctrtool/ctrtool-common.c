#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/uio.h>
#include <syscall.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
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
int ctrtool_close_range(int min_fd, int max_fd, unsigned int flags) {
	if (min_fd < 0) {
		errno = EINVAL;
		return -1;
	}
	if (max_fd < 0) {
		errno = EINVAL;
		return -1;
	}
#ifdef SYS_close_range
	return syscall(SYS_close_range, min_fd, max_fd, flags, 0, 0, 0);
#elif defined(__x86_64__) || defined(__i386__)
	return syscall(436, min_fd, max_fd, flags, 0, 0, 0);
#else
	errno = ENOSYS;
	return -1;
#endif
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
int ctrtool_arraylist_expand(struct ctrtool_arraylist *list, const void *new_element, size_t step) {
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
	memcpy(&((char *) list->start)[list->nr * list->elem_size], new_element, list->elem_size);
	list->nr = new_list_size;
	return 0;
}
