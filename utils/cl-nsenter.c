#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
static int cl_enter_proc(int proc_fd, const char *name, int nstype, int req_mask, int close_proc_fd) {
	if (!(req_mask & nstype)) {
		if (close_proc_fd) {
			close(proc_fd);
		}
		return 0;
	}
	int fd = openat(proc_fd, name, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
	if (close_proc_fd) {
		close(proc_fd);
	}
	if (fd < 0) return -1;
	int return_value = setns(fd, nstype);
	close(fd);
	return -!!return_value;
}
int cl_nsenter_params(const char *param) {
	int flags = 0;
	const char *p = param;
	int fd = -1;
	int fd_type = 0;
	int close_fd = 0;
	while (1) {
		switch (*p) {
			case 'C':
				flags |= CLONE_NEWCGROUP;
				break;
			case 'i':
				flags |= CLONE_NEWIPC;
				break;
			case 'm':
				flags |= CLONE_NEWNS;
				break;
			case 'n':
				flags |= CLONE_NEWNET;
				break;
			case 'p':
				flags |= CLONE_NEWPID;
				break;
			case 'U':
				flags |= CLONE_NEWUSER;
				break;
			case 'u':
				flags |= CLONE_NEWUTS;
				break;
			case 'X':
				close_fd = 1;
				break;
			case ':':
				if (!isdigit(p[1])) {
					return -2;
				}
				fd = atoi(&p[1]);
				goto end_while;
			case '-':
				;
				const char *envvar_name = &p[1];
				if (!*envvar_name) envvar_name = "CTRTOOL_CONTAINER_LAUNCHER_PID_FD";
				char *env_value = getenv(envvar_name);
				if (!env_value) {
					return -3;
				}
				if (!isdigit(env_value[0])) {
					return -3;
				}
				fd = atoi(env_value);
				goto end_while;
			case '=':
				fd = open(&p[1], O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
				if (fd == -1) return -1;
				fd_type = 1;
				goto end_while;
			case '/':
				fd = open(&p[1], O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY|O_DIRECTORY);
				if (fd == -1) return -1;
				fd_type = 2;
				goto end_while;
			default:
				return -2;
		}
		p++;
	}
end_while:
	switch (fd_type) {
		case 0:
			;
			int rv = -!!setns(fd, flags);
			if (close_fd) close(fd);
			return rv;
		case 1:
			;
			int return_value = -!!setns(fd, flags);
			close(fd);
			return return_value;
		case 2:
			if (cl_enter_proc(fd, "ns/user", CLONE_NEWUSER, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/cgroup", CLONE_NEWCGROUP, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/ipc", CLONE_NEWIPC, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/net", CLONE_NEWNET, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/uts", CLONE_NEWUTS, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/pid", CLONE_NEWPID, flags, 0)) return -1;
			if (cl_enter_proc(fd, "ns/mnt", CLONE_NEWNS, flags, 1)) return -1;
			return 0;
	}
	return -1;
}
