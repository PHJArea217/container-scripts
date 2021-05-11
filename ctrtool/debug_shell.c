#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
int ctr_scripts_debug_shell_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	int accept_fd = 0;
	int opt = 0;
	char **shell_command = NULL;
	size_t shell_command_len = 0;
	int do_listen = 0;
	int force_unix = 1;
	while ((opt = getopt(argc, argv, "+c:f:luE")) > 0) {
		switch (opt) {
			case 'c':
				shell_command = reallocarray(shell_command, ++shell_command_len, sizeof(char *));
				if (!shell_command) {
					return 1;
				}
				shell_command[shell_command_len-1] = ctrtool_strdup(optarg);
				break;
			case 'f':
				accept_fd = atoi(optarg);
				break;
			case 'l':
				do_listen = 1;
				break;
			case 'u':
				force_unix = 1;
				break;
			case 'E':
				force_unix = 0;
				break;
			default:
				return -1;
		}
	}
	if (shell_command_len == 0) {
		fprintf(stderr, "%s: -c command required\n", argv[0]);
		return 1;
	}
	shell_command = reallocarray(shell_command, ++shell_command_len, sizeof(char *));
	if (!shell_command) {
		return 1;
	}
	shell_command[shell_command_len-1] = NULL;
	if (do_listen) {
		if (listen(accept_fd, SOMAXCONN)) {
			perror("listen");
			return 1;
		}
	} else {
		opt = 0;
		socklen_t optsize = sizeof(int);
		if (getsockopt(accept_fd, SOL_SOCKET, SO_ACCEPTCONN, &opt, &optsize)) {
			perror("getsockopt");
			return 1;
		}
		if ((optsize != sizeof(int)) || (!opt)) {
			fprintf(stderr, "The socket must be an accepting socket\n");
			return 1;
		}
	}
	if (force_unix) {
		opt = 0;
		socklen_t optsize = sizeof(int);
		if (getsockopt(accept_fd, SOL_SOCKET, SO_DOMAIN, &opt, &optsize)) {
			perror("getsockopt");
			return 1;
		}
		if ((optsize != sizeof(int)) || (opt != AF_UNIX)) {
			fprintf(stderr, "The socket must be of type AF_UNIX, use -E to override\n");
			return 1;
		}
	}
	if (accept_fd < 3) {
		int accept_replace_fd = fcntl(accept_fd, F_DUPFD, 3);
		if (accept_replace_fd == -1) {
			perror("fcntl");
			return 1;
		}
		int replacement_fd = open("/dev/null", O_RDWR|O_NOCTTY);
		if (replacement_fd == -1) {
			perror("open /dev/null");
			return 1;
		}
		if (dup2(replacement_fd, accept_fd) != accept_fd) return 1;
		close(replacement_fd);
		accept_fd = accept_replace_fd;
	}
	if (argv[optind]) {
		/* In the current process, exec the specified program. Continue running our stuff in the forked process. */
		pid_t child_pid = fork();
		if (child_pid < 0) {
			perror("fork");
			return 1;
		}
		if (child_pid > 0) {
			close(accept_fd);
			execvp(argv[optind], &argv[optind]);
			_exit(127);
			return 127;
		}
		if (setsid() < 0) _exit(255);
	}
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) _exit(255);
	while (1) {
		int new_fd = accept(accept_fd, NULL, NULL);
		if (new_fd < 0) {
			nanosleep(&(struct timespec) {0, 10000000}, NULL);
			continue;
		}
		pid_t child_pid = fork();
		if (child_pid == 0) {
			close(accept_fd);
			if (setsid() < 0) _exit(255);
			if (dup2(new_fd, 0) != 0) _exit(255);
			if (dup2(new_fd, 1) != 1) _exit(255);
			if (new_fd > 1) close(new_fd);
			if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) _exit(255);
			execvp(shell_command[0], shell_command);
			_exit(127);
			return 127;
		}
		close(new_fd);
	}
}
