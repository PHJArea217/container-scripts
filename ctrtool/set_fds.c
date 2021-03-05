#include <sys/types.h>
#include "ctrtool-common.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
int ctr_scripts_set_fds_main(int argc, char **argv) {
	char *fd_list = NULL;
	int do_set_listen_fds = 0;
	int opt = 0;
	while ((opt = getopt(argc, argv, "+f:s")) > 0) {
		switch (opt) {
			case 'f':
				free(fd_list);
				fd_list = strdup(optarg);
				if (fd_list == NULL) return 1;
				break;
			case 's':
				do_set_listen_fds = 1;
				break;
			default:
				return 1;
		}
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return 1;
	}
	int *fd_list_b = NULL;
	size_t list_s = 0;
	size_t list_m = 0;
	if (fd_list) {
		char *saveptr = NULL;
		for (char *s = strtok_r(fd_list, ",", &saveptr); s; s = strtok_r(NULL, ",", &saveptr)) {
			if (!isdigit(*s)) {
				fprintf(stderr, "fd_list must be a series of numbers separated by commas\n");
				return 1;
			}
			list_s++;
			if (list_s > list_m) {
				list_m += 25;
				fd_list_b = reallocarray(fd_list_b, list_m, sizeof(int));
				if (fd_list_b == NULL) return 1;
			}
			fd_list_b[list_s-1] = atoi(s);
		}
		free(fd_list);
	}
	if (do_set_listen_fds) {
		ctrtool_mini_init_set_listen_pid_fds(list_s);
	}
	ctrtool_mini_init_set_fds(fd_list_b, list_s);
	execvp(argv[optind], &argv[optind]);
	return 127;
}
