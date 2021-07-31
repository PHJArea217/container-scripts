#define _GNU_SOURCE
#include "ctrtool-common.h"
#include "ctrtool_nsof.h"
#include "ctrtool_options.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <stdio.h>
#include <wait.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#define NR_REGS 8
static int do_memfd(unsigned int actual_type) {
	int retval = -1;
	switch (actual_type) {
		case CTRTOOL_NSOF_SPECIAL_MEMFD:
			retval = memfd_create("", 0);
			break;
		case CTRTOOL_NSOF_SPECIAL_MEMFD_SEAL:
			retval = memfd_create("", MFD_ALLOW_SEALING);
			break;
		default:
			errno = ENOSYS;
			return -1;
	}
	if (retval < 0) {
		return -1;
	}
	if (fchmod(retval, 0600)) {
		close(retval);
		return -1;
	}
	return retval;
}
static int do_popen(struct ns_open_file_req *req) {
	if (!req->file_path) {
		fprintf(stderr, "Shell command required for -I popen_*\n");
		errno = ENODATA;
		return -1;
	}
	int fd_pair[2] = {-1, -1}; /* 0 = this process, 1 = child process */
	switch (req->i_subtype) {
		case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD:
		case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL:
			if ((fd_pair[0] = do_memfd((req->i_subtype == CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL) ? CTRTOOL_NSOF_SPECIAL_MEMFD_SEAL : CTRTOOL_NSOF_SPECIAL_MEMFD)) < 0) {
				return -1;
			}
			fd_pair[1] = fd_pair[0];
			break;
		case CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_READ:
			if (pipe(fd_pair)) {
				return -1;
			}
			break;
		case CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_WRITE:
			if (1) {
				int fd_pair_tmp[2];
				if (pipe(fd_pair_tmp)) {
					return -1;
				}
				fd_pair[0] = fd_pair_tmp[1];
				fd_pair[1] = fd_pair_tmp[0];
			}
			break;
		case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDIN:
		case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDOUT:
		case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_SCM_FD:
		case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_BOTH:
			if (socketpair(AF_UNIX, req->sock_type, 0, fd_pair)) {
				return -1;
			}
			break;
		default:
			/* FIXME: plain popen (without fd) */
			errno = ENOSYS;
			return -1;
			break;
	}
	pid_t child_pid = fork();
	if (child_pid < 0) {
		goto close_fail;
	}
	if (child_pid == 0) {
		switch (req->i_subtype) {
			case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_BOTH:
				if (dup2(fd_pair[1], 1) != 1) {
					ctrtool_exit(127);
				}
			case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDIN:
			case CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_WRITE:
				close(fd_pair[0]);
				if (dup2(fd_pair[1], 0) != 0) {
					ctrtool_exit(127);
				}
				break;
			case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDOUT:
			case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_SCM_FD:
			case CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_READ:
				close(fd_pair[0]);
			case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD:
			case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL:
				if (dup2(fd_pair[1], 1) != 1) {
					ctrtool_exit(127);
				}
				break;
		}
		if (fd_pair[1] >= 3) close(fd_pair[1]);
		char *argv_list[] = {"sh", "-c", (char *) req->file_path, NULL};
		execvp("sh", argv_list);
		ctrtool_exit(127);
	} else {
		switch (req->i_subtype) {
			case CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_SCM_FD:
				if (fd_pair[1] >= 3) close(fd_pair[1]);
				fd_pair[1] = -1;
			case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD:
			case CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL:
				;int w_status = 0x7f00;
				if (waitpid(child_pid, &w_status, 0) != child_pid) {
					goto close_fail;
				}
				if (WIFEXITED(w_status)) {
					int exit_status = WEXITSTATUS(w_status);
					if (exit_status) {
						fprintf(stderr, "Command failed (exit = %d)\n", exit_status);
						goto close_fail;
					}
				} else if (WIFSIGNALED(w_status)) {
					int exit_status = WTERMSIG(w_status);
					fprintf(stderr, "Command failed (sig = %d)\n", exit_status);
					goto close_fail;
				}
				if (req->i_subtype == CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_SCM_FD) {
					int recv_fd = ctrtool_unix_scm_recv(fd_pair[0]);
					if (recv_fd < 0) {
						close(fd_pair[0]);
						return -1;
					}
					close(fd_pair[0]);
					return recv_fd;
				}
				if (req->i_subtype == CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL) {
					if (fcntl(fd_pair[0], F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) {
						goto close_fail;
					}
				}
				if (lseek(fd_pair[0], 0, SEEK_SET)) {
					goto close_fail;
				}
				break;
			default:
				if (fd_pair[1] >= 3) close(fd_pair[1]);
				break;
		}
	}
	return fd_pair[0];
close_fail:
	if (fd_pair[0] == fd_pair[1]) {
		close(fd_pair[0]);
	} else {
		close(fd_pair[0]);
		close(fd_pair[1]);
	}
	return -1;
}
static int do_ifne_poll(int fd, int is_ifne) {
	struct pollfd pfd = {fd, POLLIN, 0};
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}
	if (poll(&pfd, 1, -1) != 1) return -1;
	if (pfd.revents & POLLNVAL) {
		errno = EBADF;
		return -1;
	}
	if (is_ifne) {
		if (pfd.revents & POLLIN) return 0;
		errno = ENODATA;
		return -1;
	}
	return 0;
}
static int do_connect(int op_fd, int a_fd, struct ns_open_file_req *req) {
	if (req->i_subtype == CTRTOOL_NSOF_SPECIAL_CONNECT_UNIX_PATH) {
		if (a_fd < 0) {
			errno = EBADF;
			return -1;
		}
		struct sockaddr_un proc_path = {AF_UNIX, {0}};
		if (snprintf(proc_path.sun_path, sizeof(proc_path.sun_path), "/proc/self/fd/%d", a_fd) <= 0) {
			errno = ENOMEM;
			return -1;
		}
		if (connect(op_fd, &proc_path, sizeof(proc_path))) {
			if (errno == EINPROGRESS) {
				return 0;
			}
			return -1;
		}
		return 0;
	}
	if (!req->bind_address) {
		errno = ENODATA;
		return -1;
	}
	if (connect(op_fd, req->bind_address, req->bind_address_len)) {
		if (errno == EINPROGRESS) {
			return 0;
		}
		return -1;
	}
	return 0;
}
static int do_ptslave(int op_fd, struct ns_open_file_req *req) {
	if (unlockpt(op_fd)) return -1;
	/* FIXME: If we ever need to support non-linux systems, we should still use
	 * ptsname or similar. Don't forget to grantpt()! */
	int slave_fd = ioctl(op_fd, TIOCGPTPEER, req->openat2_how.flags);
	if (slave_fd < 0) return -1;
	return slave_fd;
}
static int do_tunsetiff(int op_fd, struct ns_open_file_req *req) {
	const char *default_tun = "tun%d";
	if (req->file_path) {
		default_tun = req->file_path;
	}
	if (strnlen(default_tun, IFNAMSIZ) >= IFNAMSIZ) {
		errno = ENAMETOOLONG;
		return -1;
	}
	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, default_tun, sizeof(ifr.ifr_name));
	ifr.ifr_flags = req->sock_type; /* Weird, but it allows us to reuse -t for this */
	if (ioctl(op_fd, TUNSETIFF, &ifr)) {
		return -1;
	}
	return 0;
}
int ctrtool_nsof_process_special(struct ns_open_file_req *req, const int *register_list) {
	if (req->i_subtype >= 0x100000) {
		errno = ENOSYS;
		return -1;
	}
	int op_fd = -1;
	int a_fd = -1;
	if (req->ns_path_is_register) {
		int reg_num = req->ns_path_register;
		ctrtool_assert(reg_num >= 0 && reg_num < NR_REGS);
		op_fd = register_list[reg_num];
	}
	if (req->has_ureg1) {
		int reg_num = req->u_reg1;
		ctrtool_assert(reg_num >= 0 && reg_num < NR_REGS);
		a_fd = register_list[reg_num];
	}
	switch (req->i_subtype & CTRTOOL_NSOF_SPECIAL_MAJOR_MASK) {
		case CTRTOOL_NSOF_SPECIAL_MAJOR_MEMFD:
			return do_memfd(req->i_subtype);
		case CTRTOOL_NSOF_SPECIAL_MAJOR_POPEN:
			return do_popen(req);
		default:
			switch (req->i_subtype) {
				case CTRTOOL_NSOF_SPECIAL_POLL:
					return do_ifne_poll(op_fd, 0) == 0 ? -150 : -1;
				case CTRTOOL_NSOF_SPECIAL_IFNE:
					return do_ifne_poll(op_fd, 1) == 0 ? -150 : -1;
				case CTRTOOL_NSOF_SPECIAL_CONNECT:
				case CTRTOOL_NSOF_SPECIAL_CONNECT_UNIX_PATH:
					return do_connect(op_fd, a_fd, req) == 0 ? -150 : -1;
				case CTRTOOL_NSOF_SPECIAL_SCM_RIGHTS_RECV_ONE:
					return ctrtool_unix_scm_recv(op_fd);
				case CTRTOOL_NSOF_SPECIAL_SCM_RIGHTS_SEND_ONE:
					return ctrtool_unix_scm_send(op_fd, a_fd) == 0 ? -150 : -1;
				case CTRTOOL_NSOF_SPECIAL_PTSLAVE:
					return do_ptslave(op_fd, req);
				case CTRTOOL_NSOF_SPECIAL_TUNSETIFF:
					return do_tunsetiff(op_fd, req) == 0 ? -150 : -1;
			}
	}
	errno = ENOSYS;
	return -1;
}
static struct ctrtool_opt_element cred_opts[] = {
	{.name = "gid", .value = {.value = 1}},
	{.name = "groups", .value = {.value = 2}},
	{.name = "keepcaps", .value = {.value = 3}},
	{.name = "keep_groups", .value = {.value = 8}},
	{.name = "pre_gid", .value = {.value = 4}},
	{.name = "pre_uid", .value = {.value = 5}},
	{.name = "setgroups_pre", .value = {.value = 6}},
	{.name = "uid", .value = {.value = 7}},
	{.name = "unix_gid", .value = {.value = 9}},
};
int ctrtool_nsof_cmdline_creds(const char *arg, struct ns_open_file_req *req) {
	struct ctrtool_opt_kv *res = ctrtool_options_parse_arg_kv(arg, cred_opts, sizeof(cred_opts)/sizeof(cred_opts[0]));
	if (!res) {
		return -1;
	}
	int has_error = 0;
	uint64_t parse_result = 0;
	switch (res->key) {
		case 9:
			if (req->type != CTRTOOL_NS_OPEN_FILE_NETWORK_SOCKET) {
				errno = EINVAL;
				goto out;
			}
		case 1:
		case 4:
		case 5:
		case 7:
			parse_result = ctrtool_options_parse_arg_int(res->value, NULL, &has_error, -1ULL);
			if (has_error || (parse_result >= 4294967295)) {
				goto out;
			}
			switch (res->key) {
				case 1:
					req->have_credential_change = 1;
					req->userns_gid = parse_result;
					req->userns_have_gid = 1;
					break;
				case 4:
					req->have_credential_change = 1;
					req->pre_enter_gid = parse_result;
					req->pre_enter_have_gid = 1;
					break;
				case 5:
					req->have_credential_change = 1;
					req->pre_enter_uid = parse_result;
					req->pre_enter_have_uid = 1;
					break;
				case 7:
					req->have_credential_change = 1;
					req->userns_uid = parse_result;
					req->userns_have_uid = 1;
					break;
				case 9:
					req->unix_group = parse_result;
					req->unix_set_group = 1;
					break;
			}
			break;
		case 2:
			;struct iovec gid_result = {NULL, 0};
			if (ctrtool_parse_int_array(res->value, &gid_result, sizeof(gid_t))) {
				goto out;
			}
			req->userns_groups = gid_result.iov_base;
			req->userns_ngroups = gid_result.iov_len;
			req->userns_have_groups = 1;
			req->have_credential_change = 1;
			break;
		case 3:
			req->userns_keepcaps = 1;
			req->have_credential_change = 1;
			break;
		case 6:
			req->userns_groups_pre = 1;
			req->have_credential_change = 1;
			break;
		case 8:
			req->pre_enter_keep_groups = 1;
			req->have_credential_change = 1;
			break;
		default:
			abort();
			break;
	}
	free(res);
	return 0;
out:
	free(res);
	return -1;
}
int ctrtool_nsof_set_creds_pre(struct ns_open_file_req *req) {
	if (!req->pre_enter_keep_groups) {
		if (req->userns_have_groups && req->userns_groups_pre) {
			if (setgroups(req->userns_ngroups, req->userns_groups)) return -1;
		} else if (req->pre_enter_have_gid || req->userns_have_gid) {
			if (setgroups(0, NULL)) return -1;
		}
	}
	if (req->pre_enter_have_gid) {
		if (setresgid(req->pre_enter_gid, -1, -1)) return -1;
	}
	if (req->pre_enter_have_uid) {
		if (setresuid(req->pre_enter_uid, -1, -1)) return -1;
	}
	if (ctrtool_load_permitted_caps()) return -1;
	return 0;
}
int ctrtool_nsof_set_creds_post(struct ns_open_file_req *req) {
	if (req->userns_have_groups && !req->userns_groups_pre) {
		if (setgroups(req->userns_ngroups, req->userns_groups)) {
			return -1;
		}
	}
	if (req->userns_have_gid) {
		if (setresgid(req->userns_gid, -1, -1)) return -1;
	}
	if (req->userns_have_uid) {
		if (setresuid(req->userns_uid, -1, -1)) return -1;
	}
	if (req->userns_keepcaps) {
		if (ctrtool_load_permitted_caps()) return -1;
	}
	return 0;
}
