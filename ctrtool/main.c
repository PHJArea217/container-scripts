#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int ctr_scripts_container_launcher_main(int argc, char **argv);
int ctr_scripts_container_rootfs_mount_main(int argc, char **argv);
int ctr_scripts_mini_init_main(int argc, char **argv);
int ctr_scripts_mini_init2_main(int argc, char **argv);
int ctr_scripts_mount_seq_main(int argc, char **argv);
int ctr_scripts_reset_cgroup_main(int argc, char **argv);
int ctr_scripts_simple_renameat2_main(int argc, char **argv);
int ctr_scripts_debug_shell_main(int argc, char **argv);
int ctr_scripts_set_fds_main(int argc, char **argv);
struct command_def {
	const char *name;
	int (*main_function)(int, char **);
};
static struct command_def command_list[] = {
	{"container-launcher", ctr_scripts_container_launcher_main},
	{"container-rootfs-mount", ctr_scripts_container_rootfs_mount_main},
	{"debug_shell", ctr_scripts_debug_shell_main},
	{"init", ctr_scripts_mini_init_main},
	{"init2", ctr_scripts_mini_init2_main},
	{"launcher", ctr_scripts_container_launcher_main},
	{"mini-init", ctr_scripts_mini_init_main},
	{"mini-init2", ctr_scripts_mini_init2_main},
	{"mount_seq", ctr_scripts_mount_seq_main},
	{"renameat2", ctr_scripts_simple_renameat2_main},
	{"reset_cgroup", ctr_scripts_reset_cgroup_main},
	{"rootfs-mount", ctr_scripts_container_rootfs_mount_main},
	{"set_fds", ctr_scripts_set_fds_main},
	{"simple-renameat2", ctr_scripts_simple_renameat2_main},
};
static int compare_command_def(const void *a, const void *b) {
	return strcmp(((struct command_def *) a)->name, ((struct command_def *) b)->name);
}
static int search_command(const char *base_command, int argc, char **argv) {
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
		return result->main_function(argc, argv);
	}
	fprintf(stderr, "ctrtool: %s not found, if executing using different name, set $CTRTOOL_OVERRIDE_ARGV0_LOOKUP to 1\n", base_command);
	return 255;
}
int main(int argc, char **argv) {
	while (1) {
		int dummy_socket = socket(AF_UNIX, SOCK_STREAM, 0);
		if (dummy_socket == -1) return 1;
		if (dummy_socket >= 3) {
			close(dummy_socket);
			break;
		}
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
	if ((strlen(base_command_c) >= 7) && (memcmp(base_command_c, "ctrtool", 7) == 0)) {
		goto default_lookup;
	}
	return search_command(argv[0], argc, argv);
default_lookup:
	if (argc < 2) {
		fprintf(stderr, "Usage: %s [debug_shell|init|launcher|mount_seq|renameat2|reset_cgroup|rootfs-mount|set_fds] [ARGUMENTS]\n", argv[0]);
		return 255;
	}
	return search_command(argv[1], argc-1, &argv[1]);
}
