#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
int ctr_scripts_simple_renameat2_main(int argc, char **argv) {
	int source_fd = AT_FDCWD;
	int target_fd = AT_FDCWD;
	int rename_flags = 0;
	int opt = 0;
	while ((opt = getopt(argc, argv, "xwns:d:")) > 0) {
		switch (opt) {
			case 'x':
				rename_flags |= RENAME_EXCHANGE;
				break;
			case 'w':
				rename_flags |= RENAME_WHITEOUT;
				break;
			case 'n':
				rename_flags |= RENAME_NOREPLACE;
				break;
			case 's':
				source_fd = atoi(optarg);
				break;
			case 'd':
				target_fd = atoi(optarg);
				break;
			default:
				fprintf(stderr, "Usage: %s [-xwn] [-s source_fd] [-d target_fd] source_file target_file\n", argv[0]);
				return 2;
				break;
		}
	}
	const char *source_filename = argv[optind];
	if (!source_filename) goto two_args_required;
	const char *dest_filename = argv[optind+1];
	if (!dest_filename) goto two_args_required;
	const char *x_filename = argv[optind+2];
	if (x_filename) goto two_args_required;
	if (renameat2(source_fd, source_filename, target_fd, dest_filename, rename_flags)) {
		fprintf(stderr, "Move %s to %s failed: %s\n", source_filename, dest_filename, strerror(errno));
		return 1;
	}
	return 0;
two_args_required:
	fprintf(stderr, "%s: exactly 2 arguments required\n", argv[0]);
	return 2;
}
