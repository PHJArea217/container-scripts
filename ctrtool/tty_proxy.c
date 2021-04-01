#define _GNU_SOURCE
#include "ctrtool_tty_proxy.h"
#include "ctrtool-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <wait.h>
#include <unistd.h>
int ctr_scripts_tty_proxy_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	struct ctrtool_tty_proxy proxy_object = {0};
	while (1) {
		int opt = getopt(argc, argv, "+w:h:p:Te");
		if (opt <= 0) break;
		switch (opt) {
			case 'w':
				proxy_object.width = atoi(optarg);
				break;
			case 'h':
				proxy_object.height = atoi(optarg);
				break;
			case 'p':
				proxy_object.ptmx_file = optarg;
				break;
			case 'T':
				proxy_object.use_stdio_pipe = 1;
				break;
			case 'e':
				proxy_object.use_stderr_pipe = 1;
				break;
			default:
				return -1;
		}
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return -1;
	}
	if (ctrtool_open_tty_proxy(&proxy_object)) {
		perror("ctrtool_open_tty_proxy");
		return -1;
	}
	int s_pipe[2];
	if (pipe2(s_pipe, O_CLOEXEC)) {
		perror("pipe");
		return -1;
	}
	pid_t child_pid = fork();
	if (child_pid < 0) {
		perror("fork");
		return -1;
	}
	if (child_pid == 0) {
		close(s_pipe[0]);
		if (setsid() < 0) {
			perror("setsid");
			_exit(-1);
		}
		if (ctrtool_tty_proxy_child(&proxy_object)) {
			perror("ctrtool_tty_proxy_child");
			_exit(-1);
		}
		if (write(s_pipe[1], "X", 1) != 1) {
			perror("write");
			_exit(-1);
		}
		close(s_pipe[1]);
		execvp(argv[optind], &argv[optind]);
		perror("execvp");
		_exit(127);
	} else {
		close(s_pipe[1]);
		ctrtool_tty_proxy_master(&proxy_object, 1);
		char buf = 0;
		if (read(s_pipe[0], &buf, 1) != 1) {
			perror("read");
			return -1;
		}
		close(s_pipe[0]);
		if (buf != 'X') {
			perror("read");
			return -1;
		}
		int wait_status = 0xff00;
		int mainloop_result = ctrtool_tty_proxy_mainloop(&proxy_object, child_pid, &wait_status);
		if (mainloop_result < 0) {
			perror("ctrtool_tty_proxy_mainloop");
			return -1;
		}
		if (WIFEXITED(wait_status)) return WEXITSTATUS(wait_status);
		if (WIFSIGNALED(wait_status)) return WTERMSIG(wait_status);
	}
	return -1;
}
