#define _GNU_SOURCE
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <errno.h>
#include "ctrtool-common.h"
int ctr_scripts_chroot_pivot_main(int argc, char **argv);
int ctr_scripts_container_launcher_main(int argc, char **argv);
int ctr_scripts_container_rootfs_mount_main(int argc, char **argv);
int ctr_scripts_mini_init_main(int argc, char **argv);
int ctr_scripts_mini_init2_main(int argc, char **argv);
int ctr_scripts_mount_seq_main(int argc, char **argv);
int ctr_scripts_ns_open_file_main(int argc, char **argv);
int ctr_scripts_pidfd_ctl_main(int argc, char **argv);
int ctr_scripts_reset_cgroup_main(int argc, char **argv);
int ctr_scripts_simple_renameat2_main(int argc, char **argv);
int ctr_scripts_debug_shell_main(int argc, char **argv);
int ctr_scripts_set_fds_main(int argc, char **argv);
int ctr_scripts_syslogd_main(int argc, char **argv);
int ctr_scripts_tty_proxy_main(int argc, char **argv);
struct command_def {
	const char *name;
	int (*main_function)(int, char **);
};
static int search_command(const char *base_command, int argc, char **argv, int from_escape);
static int ctr_scripts_escape_main(int argc, char **argv) {
	if (argc < 2) {
		fputs("ctrtool_escape: Command required\n", stderr);
		return 255;
	}
	if (ctrtool_escape()) {
		perror("ctrtool_escape");
		return 255;
	}
	return search_command(argv[1], argc - 1, &argv[1], 1);
}
static struct command_def command_list[] = {
	{"_ctrtool_escaped", ctr_scripts_escape_main},
	{"chroot_pivot", ctr_scripts_chroot_pivot_main},
	{"container-launcher", ctr_scripts_container_launcher_main},
	{"container-rootfs-mount", ctr_scripts_container_rootfs_mount_main},
	{"debug_shell", ctr_scripts_debug_shell_main},
	{"escape", ctr_scripts_escape_main},
	{"init", ctr_scripts_mini_init_main},
	{"init2", ctr_scripts_mini_init2_main},
	{"launcher", ctr_scripts_container_launcher_main},
	{"mini-init", ctr_scripts_mini_init_main},
	{"mini-init2", ctr_scripts_mini_init2_main},
	{"mount_seq", ctr_scripts_mount_seq_main},
	{"ns_open_file", ctr_scripts_ns_open_file_main},
	{"pidfd_ctl", ctr_scripts_pidfd_ctl_main},
	{"renameat2", ctr_scripts_simple_renameat2_main},
	{"reset_cgroup", ctr_scripts_reset_cgroup_main},
	{"rootfs-mount", ctr_scripts_container_rootfs_mount_main},
	{"set_fds", ctr_scripts_set_fds_main},
	{"simple-renameat2", ctr_scripts_simple_renameat2_main},
	{"syslogd", ctr_scripts_syslogd_main},
	{"tty_proxy", ctr_scripts_tty_proxy_main}
};
static int compare_command_def(const void *a, const void *b) {
	return strcmp(((struct command_def *) a)->name, ((struct command_def *) b)->name);
}
static int search_command(const char *base_command, int argc, char **argv, int from_escape) {
	const char *base_command_c = base_command;
	char *f = strrchr(base_command_c, '/');
	if (f) {
		base_command_c = &f[1];
	}
	struct command_def key_lookup = {base_command_c, NULL};
	struct command_def *result = bsearch(&key_lookup, &command_list, sizeof(command_list)/sizeof(command_list[0]), sizeof(struct command_def), compare_command_def);
	if (result) {
		if (!argv[0]) {
			fprintf(stderr, "BUG: argv[0] was NULL!\n");
			return 255;
		}
		if (from_escape && (result->main_function == ctr_scripts_escape_main)) {
			fprintf(stderr, "Multiple use of escape command not allowed\n");
			return 255;
		}
		exit(result->main_function(argc, argv));
		abort();
	}
	fprintf(stderr, "ctrtool: %s not found, if executing using different name, set $CTRTOOL_OVERRIDE_ARGV0_LOOKUP to 1\n", base_command);
	return 255;
}
int main(int argc, char **argv) {
	errno = 0;
	while (1) {
//		int dummy_socket = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
		int dummy_socket = eventfd(0, EFD_NONBLOCK);
		if (dummy_socket < 0) return -1;
		if (dummy_socket >= 3) {
			close(dummy_socket);
			break;
		}
	}
	if (ctrtool_save_argv(argc, argv)) {
		perror("ctrtool_save_argv");
		return -1;
	}
	char *override_lookup = getenv("CTRTOOL_OVERRIDE_ARGV0_LOOKUP");
	if (override_lookup && (strtoul(override_lookup, NULL, 0) > 0)) {
		goto default_lookup;
	}
	const char *base_command_c = argv[0];
	char *f = strrchr(base_command_c, '/');
	if (f) {
		base_command_c = &f[1];
	}
	size_t len_base_command_c = strnlen(base_command_c, 7);
	if ((len_base_command_c >= 7) && (memcmp(base_command_c, "ctrtool", 7) == 0)) {
		goto default_lookup;
	} else if ((len_base_command_c == 3) && (memcmp(base_command_c, "exe", 3) == 0)) {
		goto default_lookup;
	}
	return search_command(argv[0], argc, argv, 0);
default_lookup:
	if (argc < 2) {
		fprintf(stderr, "Usage: %s\n"
				"\t[ escape ] [ chroot_pivot | debug_shell | init | init2 | launcher\n"
				"\t| mount_seq | ns_open_file | pidfd_ctl | renameat2 | reset_cgroup\n"
				"\t| rootfs-mount | set_fds | syslogd | tty_proxy ] [ARGUMENTS]\n"
				"\nFor more information, see https://website.peterjin.org/wiki/Help:Ctrtool\n\n", argv[0]);
		return 255;
	}
	return search_command(argv[1], argc-1, &argv[1], 0);
}
