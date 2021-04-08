#define _GNU_SOURCE
#include "config.h"
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#ifndef __NR_pidfd_getfd
#if defined(__i386__) || defined(__x86_64__)
#define __NR_pidfd_getfd 438
#endif
#endif
static int getsockopt_integer(int fd, int level, int type) {
	int result = -1;
	socklen_t len = sizeof(int);
	if (getsockopt(fd, level, type, &result, &len)) {
		return -1;
	}
	if (len != sizeof(int)) return -1;
	return result;
}
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static volatile int real_func_init = 0;

__attribute__((visibility("default")))
int bind(int fd, const struct sockaddr *addr, socklen_t len) {
	int saved_errno = errno;
	if (addr == NULL) {
		errno = EFAULT;
		return -1;
	}
	int is_valid = 0;
	struct bind_anywhere_config_line f_line = {0};

	/* Inspect addr/len, to see if we have a match w/r/t address type */
	struct sockaddr_in temp_addr = {0};
	struct sockaddr_in6 temp_addr6 = {0};
	switch (len) {
		case sizeof(struct sockaddr_in):
			memcpy(&temp_addr, addr, sizeof(struct sockaddr_in));
			if ((temp_addr.sin_family == AF_INET) && (getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) == AF_INET)) {

				f_line.target_addr.s6_addr16[5] = 0xffff;
				f_line.target_addr.s6_addr32[3] = temp_addr.sin_addr.s_addr;
				f_line.target_port_number = ntohs(temp_addr.sin_port);
				f_line.c_flags |= BIND_ANYWHERE_CFLAGS_IS_IPV4;
				is_valid = 1;
			}
			break;
		case sizeof(struct sockaddr_in6):
			memcpy(&temp_addr6, addr, sizeof(struct sockaddr_in6));
			if ((temp_addr6.sin6_family == AF_INET6) && (getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) == AF_INET6)) {
				if (temp_addr6.sin6_scope_id == 0) {
					memcpy(&f_line.target_addr, &temp_addr6.sin6_addr, sizeof(struct in6_addr));
					f_line.target_port_number = ntohs(temp_addr6.sin6_port);
					is_valid = 1;
				}
			}
			break;
		default:
			break;
	}
	if (is_valid == 0) goto do_real_bind;
	
	/* Get the flags of the original file descriptor */
	int need_cloexec = 0;
	int need_nonblock = 0;
	need_cloexec = fcntl(fd, F_GETFD, 0);
	if (need_cloexec < 0) return -1;
	need_nonblock = fcntl(fd, F_GETFL, 0);
	if (need_nonblock < 0) return -1;

	need_cloexec = !!(need_cloexec & FD_CLOEXEC);
	need_nonblock = !!(need_nonblock & O_NONBLOCK);

	/* Check the TCP/UDP type */
	int socket_type = getsockopt_integer(fd, SOL_SOCKET, SO_TYPE);
	switch (socket_type) {
		case SOCK_STREAM:
			f_line.c_flags |= BIND_ANYWHERE_CFLAGS_TCP;
			break;
		case SOCK_DGRAM:
			f_line.c_flags |= BIND_ANYWHERE_CFLAGS_UDP;
			break;
		default:
			goto do_real_bind;
	}

	/* Find the address in the list (using binary search) */
	if (!bind_anywhere_find_config_for_address(&f_line)) {
		goto do_real_bind;
	}

	/* Use a PID file descriptor to perform our magic trick */
	int pid_fd = -1;
	int close_pidfd = 0;
	int found_fd = -1;
	int close_found_fd = 0;
	if (f_line.flags & BIND_ANYWHERE_FLAGS_IS_PIDFD) {
		pid_fd = f_line.pid_or_pidfd;
	} else {
		if (f_line.pid_or_pidfd) {
			pid_fd = syscall(__NR_pidfd_open, f_line.pid_or_pidfd, 0, 0, 0, 0, 0);
			if (pid_fd == -1) {
				if (errno == ENOSYS) errno = EOPNOTSUPP;
				return -1;
			}
			close_pidfd = 1;
		} else {
			found_fd = f_line.fd_number;
		}
	}
	if (found_fd < 0) {
		found_fd = syscall(__NR_pidfd_getfd, pid_fd, f_line.fd_number, 0, 0, 0, 0);
		if (found_fd == -1) {
			if (close_pidfd) close(pid_fd);
			if (errno == ENOSYS) errno = EOPNOTSUPP;
			return -1;
		}
		close_found_fd = 1;
	}
	if (close_pidfd) close(pid_fd);

	/* Check the correct inode number, if requested */

	if (f_line.flags & BIND_ANYWHERE_FLAGS_CHECK_INODE_NUMBER) {
		struct stat orig_stat = {0};
		dev_t orig_dev = 0;
		if (fstat(fd, &orig_stat)) goto close_fail;
		orig_dev = orig_stat.st_dev;
		if (fstat(found_fd, &orig_stat)) goto close_fail;
		if (orig_stat.st_dev != orig_dev) {
			errno = EINVAL;
			goto close_fail;
		}
		if (f_line.flags & BIND_ANYWHERE_FLAGS_HAS_INODE_NUMBER) {
			uint64_t inode_64 = orig_stat.st_ino;
			if (f_line.inode_number != inode_64) {
				errno = EINVAL;
				goto close_fail;
			}
		}
	}
	
	/* Restore the nonblocking flag, if the original file descriptor requested it */
	int orig_fflags = fcntl(found_fd, F_GETFL, 0);
	if (orig_fflags < 0) goto close_fail;
	if (need_nonblock) {
		if (fcntl(found_fd, F_SETFL, orig_fflags | O_NONBLOCK)) goto close_fail;
	} else {
		if (fcntl(found_fd, F_SETFL, orig_fflags & ~O_NONBLOCK)) goto close_fail;
	}

	/* We're done! Swap the original file descriptor with the new one */
	int rv = dup3(found_fd, fd, need_cloexec ? O_CLOEXEC : 0);
	if (close_found_fd) close(found_fd);
	if (rv >= 0) {
		errno = saved_errno;
		return 0;
	}
	return -1;
close_fail:
	if (close_found_fd) close(found_fd);
	return -1;
do_real_bind:
	if (real_func_init) {
		__sync_synchronize();
		return real_bind(fd, addr, len);
	}
	abort();
	return -1;
}

__attribute__((visibility("default")))
int listen(int fd, int backlog) {
	if (getsockopt_integer(fd, SOL_SOCKET, SO_ACCEPTCONN) == 1) return 0;
	int sock_domain = getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN);
	if (sock_domain < 0) return -1;
	int sock_type = getsockopt_integer(fd, SOL_SOCKET, SO_TYPE);
	if (sock_type < 0) return -1;
	int ret = -1;
	union {
		struct sockaddr _generic;
		struct sockaddr_in inet_addr4;
		struct sockaddr_in6 inet_addr6;
	} sock_info = {{0}};
	socklen_t length = sizeof(sock_info);
	switch (sock_type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			switch (sock_domain) {
				case AF_INET:
					ret = getsockname(fd, &sock_info._generic, &length);
					if (ret < 0) return -1;
					if (sock_info._generic.sa_family == AF_INET) {
						if (sock_info.inet_addr4.sin_port == 0) {
							errno = EINVAL;
							return -1;
						}
					}
					break;
				case AF_INET6:
					ret = getsockname(fd, &sock_info._generic, &length);
					if (ret < 0) return -1;
					if (sock_info._generic.sa_family == AF_INET6) {
						if (sock_info.inet_addr6.sin6_port == 0) {
							errno = EINVAL;
							return -1;
						}
					}
					break;
			}
	}
	if (real_func_init) {
		__sync_synchronize();
		return real_listen(fd, backlog);
	}
	abort();
	return -1;
}

__attribute__((constructor)) void __bind_anywhere_init(void) {
	void *real_bind_a = dlsym(RTLD_NEXT, "bind");
	if (!real_bind_a) abort();
	void *real_listen_a = dlsym(RTLD_NEXT, "listen");
	if (!real_listen_a) abort();
	real_bind = real_bind_a;
	real_listen = real_listen_a;
	__sync_synchronize();
	real_func_init = 1;
	bind_anywhere_parse_config(getenv("BIND_ANYWHERE_CONFIG_STR"));
}
