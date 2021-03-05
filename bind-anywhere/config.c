#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <netinet/in.h>
#include <ctype.h>
#include <arpa/inet.h>
static int compare_config_lines(const void *a, const void *b) {
//	struct bind_anywhere_config_line *a_r = a;
//	struct bind_anywhere_config_line *b_r = b;
	return memcmp(a, b, offsetof(struct bind_anywhere_config_line, flags));
}
static struct bind_anywhere_config_line *config_lines_global = NULL;
static size_t config_lines_global_nr = 0;
static volatile int has_config_lines_global = 0;
int bind_anywhere_find_config_for_address(struct bind_anywhere_config_line *line) {
	if (has_config_lines_global < 2) return 0;
	__sync_synchronize();
	struct bind_anywhere_config_line *config_lines = config_lines_global;
	size_t config_lines_nr = config_lines_global_nr;

	size_t left = 0;
	size_t right = config_lines_nr;
	while (left < right) {
		size_t middle = left + (right - left) / 2;
		int compare_result = compare_config_lines(line, &config_lines[middle]);
		if (compare_result < 0) {
			if (middle == right) break;
			right = middle;
		} else if (compare_result > 0) {
			if (middle == left) break;
			left = middle;
		} else {
			memcpy(line, &config_lines[middle], sizeof(struct bind_anywhere_config_line));
			return 1;
		}
	}
	return 0;
}
void bind_anywhere_parse_config(const char *config) {
	if (config == NULL) return;
	if (config[0] == 0) return;
	char *dup_config = strdup(config);
	if (!dup_config) abort();
	struct bind_anywhere_config_line *config_lines = 0;
	size_t config_nr = 0;
	size_t config_max = 0;
	char *saveptr1 = NULL;
	const char *error_msg = "Unknown error";
	const char *error_msg2 = "unknown";
	for (char *part = strtok_r(dup_config, ",", &saveptr1); part; part = strtok_r(NULL, ",", &saveptr1)) {

		char *dup_part = strdup(part);
		if (!dup_part) abort();

		struct bind_anywhere_config_line new_line = {0};
		char *saveptr2 = NULL;

		char *a_part = strtok_r(dup_part, "/", &saveptr2);
		if (!a_part) {
			error_msg = "Missing IP address";
			goto has_error;
		}

		if (inet_pton(AF_INET6, a_part, &new_line.target_addr) != 1) {
			error_msg = "Invalid IP address";
			error_msg2 = a_part;
			goto has_error;
		}

		char *p_part = strtok_r(NULL, "/", &saveptr2);

		if (!p_part) {
			error_msg = "Missing TCP/UDP port";
			goto has_error;
		}

		if (p_part[0] == 'T') {
			new_line.c_flags = BIND_ANYWHERE_CFLAGS_TCP;
			p_part = &p_part[1];
		} else if (p_part[0] == 'U') {
			new_line.c_flags = BIND_ANYWHERE_CFLAGS_UDP;
			p_part = &p_part[1];
		}

		if (!isdigit(p_part[0])) {
			error_msg = "Invalid TCP/UDP port";
			error_msg2 = p_part;
			goto has_error;
		}

		unsigned long number = strtoul(p_part, NULL, 0);
		if ((number < 0) || (number > 65535)) {
			error_msg = "Invalid TCP/UDP port";
			error_msg2 = p_part;
			goto has_error;
		}

		new_line.target_port_number = number;

		char *pid_part = strtok_r(NULL, "/", &saveptr2);

		if (!pid_part) {
			error_msg = "Missing PID or PIDFD number";
			goto has_error;
		}

		while (*pid_part) {
			switch (pid_part[0]) {
				case 'F':
					new_line.flags |= BIND_ANYWHERE_FLAGS_IS_PIDFD;
					break;
				case 'I':
					new_line.flags |= BIND_ANYWHERE_FLAGS_CHECK_INODE_NUMBER;
					break;
				case 'A':
					new_line.c_flags |= BIND_ANYWHERE_CFLAGS_IS_IPV4;
					break;
				case '.':
					break;
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
					goto pid_part_done;
				default:
					error_msg = "Invalid PID or PIDFD number or flags";
					error_msg2 = pid_part;
					goto has_error;
					break;
			}
			pid_part++;
		}
		error_msg = "Invalid PID or PIDFD number or flags";
		error_msg2 = pid_part;
		goto has_error;
pid_part_done:
		;unsigned long pid_part_i = strtoul(pid_part, NULL, 0);
		new_line.pid_or_pidfd = pid_part_i;

		char *fd_part = strtok_r(NULL, "/", &saveptr2);
		if (!fd_part) {
			error_msg = "Missing file descriptor number";
			goto has_error;
		}

		if (!isdigit(fd_part[0])) {
			error_msg = "Invalid file descriptor number";
			error_msg2 = fd_part;
			goto has_error;
		}

		new_line.fd_number = strtoul(fd_part, NULL, 0);

		char *inode_part = strtok_r(NULL, "/", &saveptr2);
		if (inode_part) {
			if (!isdigit(inode_part[0])) {
				error_msg = "Invalid inode number";
				error_msg2 = inode_part;
				goto has_error;
			}
			new_line.inode_number = strtoull(inode_part, NULL, 0);
			new_line.flags |= BIND_ANYWHERE_FLAGS_HAS_INODE_NUMBER;
		}
		free(dup_part);

		config_nr++;
		if (config_nr > config_max) {
			config_max += 10;
			config_lines = reallocarray(config_lines, sizeof(struct bind_anywhere_config_line), config_max);
			if (config_lines == NULL) {
				error_msg = "Failed to allocate memory";
				goto has_error;
			}
		}
		memcpy(&config_lines[config_nr-1], &new_line, sizeof(struct bind_anywhere_config_line));
	}
	free(dup_config);
	qsort(config_lines, config_nr, sizeof(struct bind_anywhere_config_line), compare_config_lines);
	if (__sync_bool_compare_and_swap(&has_config_lines_global, 0, 1)) {
//		__sync_synchronize();
		config_lines_global = config_lines;
		config_lines_global_nr = config_nr;
		__sync_synchronize();
		has_config_lines_global = 2;
	} else {
		error_msg = "Concurrent operation detected";
		goto has_error;
	}
	return;
has_error:
	fprintf(stderr, "%s (%s)\n", error_msg, error_msg2);
	abort();
}
