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
#include "ctrtool-common.h"
int ctr_scripts_pidfd_ctl_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		perror("signal");
		return 255;
	}
	struct ctrtool_arraylist fds_to_export = {.start = 0, .nr = 0, .max = 0, .elem_size = sizeof(int)};
	int reg_1 = -1;
	int reg_2 = -1;
	pid_t current_pid = getpid();
	while (1) {
		char tmp_buf[40] = {0};
		int opt = getopt(argc, argv, "+1:2:e:E:f:n:c:F:xI");
		if (opt <= 0) break;
		switch (opt) {
			case 'I':
				if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
					perror("signal");
					return 255;
				}
				break;
			case '1':
				reg_1 = atoi(optarg);
				break;
			case '2':
				reg_2 = atoi(optarg);
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
				long result = ctrtool_raw_syscall(SYS_clone3, &clone3_args, sizeof(clone3_args), 0, 0, 0, 0);
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
			default:
				return 254;
				break;
		}
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return 254;
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
