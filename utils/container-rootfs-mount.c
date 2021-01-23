#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
struct opt_element {
	const char *name;
	union {
		void *ptr;
		uint64_t value;
	} value;
};
struct cl_args {
	char *name;
	char *value;
};
/*
 * TODO dynamic memory allocation for this
 * May also want to put this in a common library for convenience
 */
static struct cl_args my_args[256] = {{0}};
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
static struct opt_element boolean_values[] = {
	{.name = "false", .value = {.value = 0}},
	{.name = "no", .value = {.value = 0}},
	{.name = "off", .value = {.value = 0}},
	{.name = "on", .value = {.value = 1}},
	{.name = "true", .value = {.value = 1}},
	{.name = "yes", .value = {.value = 1}}
};
static struct opt_element devfs_opts[] = {
	{.name = "bind_host", .value = {.value = 0xaaaaaaaa}},
	{.name = "none", .value = {.value = 0}},
	{.name = "symlink_host", .value = {.value = 0x55555555}}
};
static struct opt_element root_link_opts[] = {
	{.name = "all_dirs", .value = {.value = 0xffffffff}},
	{.name = "all_ro", .value = {.value = 0x55555555}},
	{.name = "all_rw", .value = {.value = 0xaaaaaaaa}},
	{.name = "none", .value = {.value = 0}},
	{.name = "usr_ro", .value = {.value = 0xaaaa5555}},
	{.name = "usr_ro_tmp", .value = {.value = 0xffff5555}},
	{.name = "usr_rw_tmp", .value = {.value = 0xffffaaaa}}
};
static size_t my_args_size = 0;
static int compare_args(const void *a, const void *b) {
	return strcasecmp(((struct cl_args *) a)->name, ((struct cl_args *) b)->name);
}
static int compare_opts(const void *a, const void *b) {
	return strcasecmp(((struct opt_element *) a)->name, ((struct opt_element *) b)->name);
}
static char *get_arg(const char *name) {
	struct cl_args req_arg = {(char *) name, 0};
	void *result = bsearch(&req_arg, my_args, my_args_size, sizeof(struct cl_args), compare_args);
	return result ? ((struct cl_args *) result)->value : NULL;
}
static uint64_t parse_arg_int(const char *arg, const char *error_msg, int *has_error, uint64_t default_value) {
	if (!arg) {
		if (has_error) *has_error = 0;
		return default_value;
	}
	if (isdigit(arg[0])) {
		if (has_error) *has_error = 0;
		return strtoull(arg, NULL, 0);
	}
	if (has_error) *has_error = 1;
	if (error_msg) {
		fprintf(stderr, "%s: %s\n", error_msg, arg);
		exit(1);
	}
	return -1;
}
static struct opt_element *parse_arg_enum(const char *arg, struct opt_element *values, size_t nr_values, const char *error_msg, int *has_error, struct opt_element *default_value) {
	if (!arg) {
		if (has_error) *has_error = 0;
		return default_value;
	}
	struct opt_element req_arg = {(char *) arg, {0}};
	void *result = bsearch(&req_arg, values, nr_values, sizeof(struct opt_element), compare_opts);
	if (result) {
		if (has_error) *has_error = 0;
		return (struct opt_element *) result;
	}
	if (has_error) *has_error = 1;
	if (error_msg) {
		fprintf(stderr, "%s: %s\n", error_msg, arg);
		exit(1);
	}
	return NULL;
}
static uint64_t parse_arg_int_with_preset(const char *arg, struct opt_element *values, size_t nr_values, const char *error_msg, uint64_t default_value) {
	if (!error_msg) {
		error_msg = "Invalid int/preset option";
	}
	int has_error = 0;
	uint64_t result = parse_arg_int(arg, NULL, &has_error, default_value);
	if (has_error) {
		struct opt_element *result2 = parse_arg_enum(arg, values, nr_values, error_msg, NULL, NULL);
		return result2->value.value;
	}
	return result;
}
static int parse_arg_bool(const char *arg, const char *error_msg, int default_value) {
	if (!error_msg) {
		error_msg = "Invalid boolean";
	}
	if (!arg) {
		return !!default_value;
	}
	int has_error = 0;
	uint64_t result = parse_arg_int(arg, NULL, &has_error, 0);
	if (has_error) {
		struct opt_element *elem = parse_arg_enum(arg, boolean_values, sizeof(boolean_values)/sizeof(boolean_values[0]), error_msg, NULL, NULL);
		return !!elem->value.value;
	}
	return !!result;
}
static char *get_arg_default(char *arg, char *default_value) {
	return arg ? arg : default_value;
}
static int check_syscall(int result, const char *error_msg) {
	if (result < 0) {
		unsigned int saved_errno = errno;
		saved_errno &= 0xff;
		if (saved_errno == 0) saved_errno = -1;
		perror(error_msg);
		exit(saved_errno);
	}
	return result;
}
int main(int argc, char **argv) {
	int opt = 0;
	while ((opt = getopt(argc, argv, "o:")) > 0) {
		switch(opt) {
			case 'o':
				if (my_args_size >= 256) {
					fprintf(stderr, "More than 256 options, please report bug!\n");
					return 1;
				}
				struct cl_args *current_arg = &my_args[my_args_size++];
				char *strdup_optarg = strdup(optarg);
				char *b = strchr(strdup_optarg, '=');
				if (!b) {
					fprintf(stderr, "No '=' character in option: %s\n", strdup_optarg);
					return 1;
				}
				*b = 0;
				b++;
				current_arg->name = strdup_optarg;
				current_arg->value = b;
				break;
			default:
				return 1;
				break;
		}
	}
	qsort(my_args, my_args_size, sizeof(struct cl_args), compare_args);
	if (!argv[optind]) {
		fprintf(stderr, "%s: Mountpoint not specified\n", argv[0]);
		return 1;
	}
	char *mount_directory = strdup(argv[optind]);
#define BOOL_FALSE(name) parse_arg_bool(get_arg(name), NULL, 0)
#define BOOL_TRUE(name) parse_arg_bool(get_arg(name), NULL, 1)
	int do_run_dirs = BOOL_TRUE("run_dirs");
	int do_tmp_world = BOOL_TRUE("tmp_world");
	int do_mqueue = BOOL_TRUE("mount_mqueue");
	int do_pts = BOOL_TRUE("mount_devpts");
	int do_sys = BOOL_FALSE("mount_sysfs");
	int do_alt_root_symlinks = BOOL_FALSE("root_symlink_usr");
	uint64_t rootfs_opts = parse_arg_int_with_preset(get_arg("root_link_opts"), root_link_opts, ARRAY_SIZE(root_link_opts), "Invalid root_link_opts", 0xaaaaaaaa);
	uint64_t dev_opts = parse_arg_int_with_preset(get_arg("dev_opts"), devfs_opts, ARRAY_SIZE(devfs_opts), "Invalid dev_opts", 0xaaaaaaaa);
	check_syscall(umask(parse_arg_int(get_arg("umask"), "Invalid umask", NULL, 022)), "umask");
	check_syscall(mount("none", mount_directory, "tmpfs", 0, get_arg_default(get_arg("tmpfs_mount_opts"), "mode=0755")), "mount tmpfs");
	check_syscall(chdir(mount_directory), "cd mount directory");
	check_syscall(mkdir("proc", 0700), "mkdir /proc");
	check_syscall(mkdir("sys", 0700), "mkdir /sys");
	check_syscall(mkdir("dev", 0777), "mkdir /dev");
	check_syscall(mkdir("dev/mqueue", 0700), "mkdir /dev/mqueue");
	check_syscall(mkdir("dev/pts", 0700), "mkdir /dev/pts");
	check_syscall(mkdir("run", 0777), "mkdir /run");
	if (do_run_dirs) {
		check_syscall(mkdir("run/lock", 0777), "mkdir /run/lock");
		check_syscall(mkdir("run/shm", 0777), "mkdir /run/shm");
		check_syscall(symlink("/run/shm", "dev/shm"), "/dev/shm");
		if (do_tmp_world) {
			check_syscall(chmod("run/lock", 01777), "chmod /run/lock");
			check_syscall(chmod("run/shm", 01777), "chmod /run/shm");
		}
	}
	check_syscall(mkdir("tmp", 0777), "mkdir /tmp");
	if (do_tmp_world) {
		check_syscall(chmod("tmp", 01777), "chmod /tmp");
	}
	if (do_pts) {
		check_syscall(mount("none", "dev/pts", "devpts", MS_NOSUID|MS_NOEXEC, "newinstance,mode=0600,ptmxmode=0666"), "mount /dev/pts");
	}
	if (do_mqueue) {
		check_syscall(mount("none", "dev/mqueue", "mqueue", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL), "mount /dev/mqueue");
	}
	if (do_sys) {
		check_syscall(mount("none", "sys", "sysfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL), "mount /sys");
	}
	const char *root_symlinks[] = {"bin", "lib", "lib32", "lib64", "libx32", "opt", "sbin", "usr", "etc", "home", "root", "var"};
	for (int i = 0; i < 12; i++) {
		const char *my_value = root_symlinks[i];
		uint8_t my_opt = (rootfs_opts >> (2 * i)) & 3;
		char tmp_buf[25] = {0};
		switch(my_opt) {
			case 0:
				break;
			case 1:
				if (do_alt_root_symlinks && ((i < 5) || (i == 6))) {
					check_syscall(snprintf(tmp_buf, sizeof(tmp_buf), "usr/%s", my_value), "snprintf");
				} else {
					check_syscall(snprintf(tmp_buf, sizeof(tmp_buf), "_fsroot_ro/%s", my_value), "snprintf");
				}
				check_syscall(symlink(tmp_buf, my_value), "symlink");
				break;
			case 2:
				check_syscall(snprintf(tmp_buf, sizeof(tmp_buf), "_fsroot_rw/%s", my_value), "snprintf");
				check_syscall(symlink(tmp_buf, my_value), "symlink");
				break;
			case 3:
				check_syscall(mkdir(my_value, (i == 10) ? 0700 : 0777), "mkdir");
				break;
		}
	}
	const char *dev_symlinks[] = {"/dev/full", "/dev/null", "/dev/random", "/dev/tty", "/dev/urandom", "/dev/zero"};
	const char *dev_symlinks_c[] = {"_host/full", "_host/null", "_host/random", "_host/tty", "_host/urandom", "_host/zero"};
	for (int i = 0; i < 6; i++) {
		const char *my_value = dev_symlinks[i];
		uint8_t my_opt = (dev_opts >> (2 * i)) & 3;
		switch(my_opt) {
			case 0:
				break;
			case 1:
				check_syscall(symlink(dev_symlinks_c[i], &my_value[1]), "symlink");
				break;
			case 2:
				check_syscall(mknod(&my_value[1], S_IFREG|0666, 0), "mknod");
				check_syscall(mount(my_value, &my_value[1], NULL, MS_BIND|MS_REC, NULL), "mount");
				break;
			case 3:
				fprintf(stderr, "Invalid option 3 for %s\n", my_value);
				exit(1);
				break;
		}
	}
	check_syscall(symlink("/proc/self/fd", "dev/fd"), "/dev/fd");
	check_syscall(symlink("fd/0", "dev/stdin"), "/dev/stdin");
	check_syscall(symlink("fd/1", "dev/stdout"), "/dev/stdout");
	check_syscall(symlink("fd/2", "dev/stderr"), "/dev/stderr");
	check_syscall(symlink("pts/ptmx", "dev/ptmx"), "/dev/ptmx");
	return 0;
}
