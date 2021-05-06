#include <sys/types.h>
#include "ctrtool-common.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
int ctr_scripts_set_fds_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	char *fd_list = NULL;
	int do_set_listen_fds = 0;
	int opt = 0;
	int do_env = 0;
	while ((opt = getopt(argc, argv, "+f:e:s")) > 0) {
		switch (opt) {
			case 'e':
				do_env = 1;
				/* fallthrough */
			case 'f':
				if (opt == 'f') do_env = 0;
				free(fd_list);
				fd_list = ctrtool_strdup(optarg);
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
			char *env_name = NULL;
			int env_num = -1;
			if (do_env) {
				int do_unset = 0;
				switch (*s) {
					case '-':
						do_unset = 1;
					case '/':
						env_name = &s[1];
						if ((*env_name == 0) || strchr(env_name, '=')) {
							fprintf(stderr, "Invalid env variable %s\n", env_name);
							return 1;
						}
						char *env_value = getenv(env_name);
						if (!env_value) {
							fprintf(stderr, "%s not set\n", env_name);
							return 1;
						}
						if ((*env_value >= '0') && (*env_value <= '9')) {
							env_num = atoi(env_value);
						} else {
							fprintf(stderr, "$%s is not a number\n", env_name);
							return 1;
						}
					case '0':
					case '1':
					case '2':
					case '3':
					case '4':
					case '5':
					case '6':
					case '7':
					case '8':
					case '9':
						break;
					default:
						fprintf(stderr, "fd_list must be a series of numbers, /ENV, or -ENV separated by commas\n");
						return 1;
				}
				if (do_unset) {
					if (unsetenv(env_name)) {
						perror("unsetenv");
						return 1;
					}
				}
			} else {
				if (!((*s >= '0') && (*s <= '9'))) {
					fprintf(stderr, "fd_list must be a series of numbers separated by commas\n");
					return 1;
				}
			}
			list_s++;
			if (list_s > list_m) {
				list_m += 25;
				fd_list_b = reallocarray(fd_list_b, list_m, sizeof(int));
				if (fd_list_b == NULL) return 1;
			}
			fd_list_b[list_s-1] = env_name ? env_num : atoi(s);
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
