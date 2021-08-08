#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <linux/sched.h>
#include <syscall.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <linux/nsfs.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <asm-generic/unistd.h>
#include "ctrtool-common.h"
static int ensure_fd_fs(int fd, unsigned int fs_type) {
	struct statfs stat_buf;
	if (fstatfs(fd, &stat_buf)) {
		return -1;
	}
	if (stat_buf.f_type == fs_type) {
		return 0;
	}
	return 1;
}
static void ensure_fd_fs_wrap(int fd, unsigned int fs_type, const char *fs_name) {
	switch (ensure_fd_fs(fd, fs_type)) {
		case -1:
			perror("fstatfs");
			exit(255);
			return;
		case 1:
			fprintf(stderr, "File descriptor %d is not of type %s\n", fd, fs_name);
			exit(253);
			return;
	}
}
int ctr_scripts_pidfd_ctl_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		perror("signal");
		return 255;
	}
	struct ctrtool_arraylist fds_to_export = {.start = 0, .nr = 0, .max = 0, .elem_size = sizeof(int)};
	int reg_1 = -1;
	int reg_2 = -1;
	int reg_3 = -1;
	pid_t current_pid = getpid();
	int require_program = 1;
	while (1) {
		char tmp_buf[40] = {0};
		int opt = getopt(argc, argv, "+I1:2:e:E:v:f:n:c:F:xyNupO");
		if (opt <= 0) break;
		switch (opt) {
			case 'I':
				if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
					perror("signal");
					return 255;
				}
				break;
			case '1':
				if (ctrtool_read_fd_env_spec(optarg, 1, &reg_1)) {
					return 255;
				}
				break;
			case '2':
				if (ctrtool_read_fd_env_spec(optarg, 1, &reg_2)) {
					return 255;
				}
				break;
			case 'e':
				if (ctrtool_arraylist_expand(&fds_to_export, &reg_1, 10)) {
					perror("ctrtool_arraylist_expand");
					return 255;
				}
				if (snprintf(tmp_buf, 40, "%d", reg_1) <= 0) {
					return 255;
				}
				if (setenv(optarg, tmp_buf, 1)) {
					perror("setenv");
					return 255;
				}
				break;
			case 'E':
				if (ctrtool_arraylist_expand(&fds_to_export, &reg_2, 10)) {
					perror("ctrtool_arraylist_expand");
					return 255;
				}
				if (snprintf(tmp_buf, 40, "%d", reg_2) <= 0) {
					return 255;
				}
				if (setenv(optarg, tmp_buf, 1)) {
					perror("setenv");
					return 255;
				}
				break;
			case 'v':
				if (ctrtool_arraylist_expand(&fds_to_export, &reg_3, 10)) {
					perror("ctrtool_arraylist_expand");
					return 255;
				}
				if (snprintf(tmp_buf, 40, "%d", reg_3) <= 0) {
					return 255;
				}
				if (setenv(optarg, tmp_buf, 1)) {
					perror("setenv");
					return 255;
				}
				break;
			case 'f':
				;struct stat st = {0};
				if (stat(optarg, &st)) {
					fprintf(stderr, "stat %s failed: %s\n", optarg, strerror(errno));
					return 255;
				}
				break;
			case 'n':
				;pid_t requested_pid = strtoul(optarg, NULL, 0);
				if (requested_pid <= 0) {
					requested_pid = current_pid;
				}
				;int pid_fd = ctrtool_syscall_errno(CTRTOOL_SYS_pidfd_open, &errno, requested_pid, 0, 0, 0, 0, 0);
				if (pid_fd < 0) {
					fprintf(stderr, "pidfd_open %lu failed: %s\n", (unsigned long) requested_pid, strerror(errno));
					return 255;
				}
				reg_1 = pid_fd;
				break;
			case 'c':
				;pid_t pid_fd_i = -1;
				struct clone_args clone3_args = {0};
				clone3_args.flags = CLONE_PIDFD;
				clone3_args.pidfd = (uint64_t) &pid_fd_i;
				clone3_args.exit_signal = SIGCHLD;
				long result = ctrtool_raw_syscall(__NR_clone3, &clone3_args, sizeof(clone3_args), 0, 0, 0, 0);
				if (result < 0) {
					fprintf(stderr, "clone() failed: %s\n", strerror(-result));
					return 255;
				}
				if (result == 0) {
					execlp("/bin/sh", "/bin/sh", "-c", optarg, NULL);
					_exit(127);
					return 127;
				}
				reg_1 = pid_fd_i;
				break;
			case 'F':
				;int fd_num = atoi(optarg);
				;long result2 = ctrtool_syscall(CTRTOOL_SYS_pidfd_getfd, reg_1, fd_num, 0, 0, 0, 0);
				if (result2 < 0) {
					fprintf(stderr, "pidfd_getfd of %d from %d failed: %s\n", fd_num, reg_1, strerror(-result2));
					return 255;
				}
				reg_2 = result2;
				break;
			case 'x':
				;int tmp = reg_1;
				reg_1 = reg_2;
				reg_2 = tmp;
				break;
			case 'y':
				tmp = reg_2;
				reg_2 = reg_3;
				reg_3 = tmp;
				break;
			case 'N':
				if (1) {
					ensure_fd_fs_wrap(reg_2, SOCKFS_MAGIC, "SOCKFS_MAGIC");
					int i_result = ioctl(reg_2, SIOCGSKNS, 0);
					if (i_result < 0) {
						perror("SIOCGSKNS");
						return 255;
					}
					reg_3 = i_result;
				}
				break;
			case 'u':
				if (1) {
					ensure_fd_fs_wrap(reg_2, NSFS_MAGIC, "NSFS_MAGIC");
					int i_result = ioctl(reg_2, NS_GET_USERNS, 0);
					if (i_result < 0) {
						perror("NS_GET_USERNS");
						return 255;
					}
					reg_3 = i_result;
				}
				break;
			case 'p':
				if (1) {
					ensure_fd_fs_wrap(reg_2, NSFS_MAGIC, "NSFS_MAGIC");
					int i_result = ioctl(reg_2, NS_GET_PARENT, 0);
					if (i_result < 0) {
						perror("NS_GET_PARENT");
						return 255;
					}
					reg_3 = i_result;
				}
				break;
			case 'O':
				if (1) {
					ensure_fd_fs_wrap(reg_2, NSFS_MAGIC, "NSFS_MAGIC");
					uid_t uid = -1;
					int i_result = ioctl(reg_2, NS_GET_OWNER_UID, &uid);
					if (i_result) {
						perror("NS_GET_OWNER_UID");
						return 255;
					}
					printf("%lu\n", (unsigned long) uid);
					fflush(stdout);
					if (ferror(stdout)) {
						perror("stdout: write error");
						return 255;
					}
					require_program = 0;
				}
				break;
			default:
				return 254;
				break;
		}
	}
	if (!argv[optind]) {
		if (require_program) {
			fprintf(stderr, "%s: No program specified\n", argv[0]);
			return 254;
		} else {
			return 0;
		}
	}
	int *list = fds_to_export.start;
	for (size_t i = 0; i < fds_to_export.nr; i++) {
		if (ctrtool_make_fd_cloexec(list[i], 0) < 0) {
			perror("ctrtool_make_fd_cloexec");
			return 255;
		}
	}
	execvp(argv[optind], &argv[optind]);
	perror("execvp()");
	return 255;
}
