#define _GNU_SOURCE
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/uio.h>
#include <syscall.h>
#include <unistd.h>
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
	syscall(SYS_writev, STDERR_FILENO, iov, 4);
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
