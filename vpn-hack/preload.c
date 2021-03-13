#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <asm-generic/fcntl.h>
#include <linux/fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static char *netns_path = NULL;
static int (*real_openat)(int, const char *, int, mode_t);
__attribute__((constructor))
void __init(void) {
	char *netns_path_v = getenv("VPNHACK_NETNS");
	if (netns_path_v) {
		netns_path_v = strdup(netns_path_v);
		if (!netns_path_v) {
			abort();
		}
		netns_path = netns_path_v;
	}
	void *real_openat_p = dlsym(RTLD_NEXT, "openat");
	if (!real_openat_p) abort();
	real_openat = real_openat_p;
}
static int _openat(int d_fd, const char *pathname, int flags, mode_t mode) {
	if (pathname == NULL) {
		errno = EFAULT;
		return -1;
	}
	if (netns_path) {
		if (strnlen(pathname, 13) == 12) {
			if (strcmp(pathname, "/dev/net/tun") == 0) {
				int netns_fd = real_openat(AT_FDCWD, netns_path, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC, 0);
				if (netns_fd < 0) {
					return -1;
				}
				if (setns(netns_fd, CLONE_NEWNET)) {
					close(netns_fd);
					return -1;
				}
				close(netns_fd);
			}
		}
	}
	return real_openat(d_fd, pathname, flags, mode);
}
__attribute__((visibility("default")))
int openat(int d_fd, const char *pathname, int flags, mode_t mode) {
	return _openat(d_fd, pathname, flags, mode);
}
__attribute__((visibility("default")))
int open(const char *pathname, int flags, mode_t mode) {
	return _openat(AT_FDCWD, pathname, flags, mode);
}
