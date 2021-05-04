#define _GNU_SOURCE
#include "ctrtool-common.h"
#include "ctrtool_options.h"
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
#include <syscall.h>
#include <signal.h>
#include <sched.h>
#include <fcntl.h>
static struct ctrtool_opt_element devfs_opts[] = {
	{.name = "bind_host", .value = {.value = 0x00000aaa}},
	{.name = "bind_host_v2", .value = {.value = 0x00002aaa}},
	{.name = "none", .value = {.value = 0}},
	{.name = "symlink_host", .value = {.value = 0x00000555}},
	{.name = "symlink_host_v2", .value = {.value = 0x00001555}}
};
static struct ctrtool_opt_element root_link_opts[] = {
	{.name = "all_dirs", .value = {.value = 0xffffffff}},
	{.name = "all_ro", .value = {.value = 0x55555555}},
	{.name = "all_rw", .value = {.value = 0xaaaaaaaa}},
	{.name = "none", .value = {.value = 0}},
	{.name = "usr_ro", .value = {.value = 0xaaaa5555}},
	{.name = "usr_ro_tmp", .value = {.value = 0xffff5555}},
	{.name = "usr_rw_tmp", .value = {.value = 0xffffaaaa}}
};
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
static int mount_proc(int pid_ns, const char *target) {
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		return -1;
	}
	long child_pid1 = ctrtool_clone_onearg(SIGCHLD);
	if (child_pid1 < 0) {
		errno = -child_pid1;
		return -1;
	}
	if (child_pid1 == 0) {
		long syscall_result = ctrtool_syscall(SYS_setns, pid_ns, CLONE_NEWPID, 0, 0, 0, 0);
		if (syscall_result < 0) {
			ctrtool_cheap_perror("setns failed", -syscall_result);
			ctrtool_exit(1);
			while (1) ;
		}
		ctrtool_syscall(SYS_close, pid_ns, 0, 0, 0, 0, 0);
		syscall_result = ctrtool_clone_onearg(SIGCHLD);
		if (syscall_result < 0) {
			ctrtool_exit(2);
			while (1) ;
		}
		if (syscall_result == 0) {
			syscall_result = ctrtool_syscall(SYS_mount, "none", target, "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL, 0);
			if (syscall_result < 0) {
				ctrtool_cheap_perror("mount /proc", -syscall_result);
				ctrtool_exit(3);
				while (1) ;
			}
			ctrtool_exit(0);
			while (1) ;
		}
x_wait1:
		;int wait_status = 0x100;
		long wait_result = ctrtool_syscall(SYS_wait4, syscall_result, &wait_status, 0, 0, 0, 0);
		if (wait_result == -EINTR) goto x_wait1;
		if (wait_result > 0) {
			if (WIFEXITED(wait_status) && (WEXITSTATUS(wait_status) == 0)) {
				ctrtool_exit(0);
			} else {
				ctrtool_exit(4);
			}
		} else {
			ctrtool_exit(3);
		}
		while (1) ;
	} else {
x_wait2:
		;int wait_status = 0x100;
		long wait_result = ctrtool_syscall(SYS_wait4, child_pid1, &wait_status, 0, 0, 0, 0);
		if (wait_result == -EINTR) goto x_wait2;
		if (wait_result > 0) {
			if (WIFEXITED(wait_status) && (WEXITSTATUS(wait_status) == 0)) {
				return 0;
			} else {
				errno = EPERM;
				return -1;
			}
		} else {
			errno = EAGAIN;
			return -1;
		}
	}
	return -1;
}
int ctr_scripts_container_rootfs_mount_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	int opt = 0;
	char *mount_proc_only = NULL;
	while ((opt = getopt(argc, argv, "o:p:t")) > 0) {
		switch(opt) {
			case 'o':
				if (ctrtool_options_add_opt(optarg)) {
					perror("ctrtool_options_add_opt");
					return 1;
				}
				break;
			case 'p':
				mount_proc_only = ctrtool_strdup(optarg);
				break;
			case 't':
				break;
			default:
				return 1;
				break;
		}
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: Mountpoint not specified\n", argv[0]);
		return 1;
	}
	ctrtool_options_sort_opts();
	char *mount_directory = ctrtool_strdup(argv[optind]);
	if (mount_proc_only) {
		int proc_fd = check_syscall(open(mount_proc_only, O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY), "PID namespace");
		free(mount_proc_only);
		check_syscall(mount_proc(proc_fd, mount_directory), "mount /proc");
		free(mount_directory);
		return 0;
	}
#define BOOL_FALSE(name) ctrtool_options_parse_arg_bool(ctrtool_options_get_arg(name), NULL, 0)
#define BOOL_TRUE(name) ctrtool_options_parse_arg_bool(ctrtool_options_get_arg(name), NULL, 1)
#define get_arg(val) ctrtool_options_get_arg(val)
#define get_arg_default(val, val2) ctrtool_options_get_arg_default(val, val2)
	int do_run_dirs = BOOL_TRUE("run_dirs");
	int do_tmp_world = BOOL_TRUE("tmp_world");
	int do_mqueue = BOOL_TRUE("mount_mqueue");
	int do_pts = BOOL_TRUE("mount_devpts");
	int do_sys = BOOL_FALSE("mount_sysfs");
	int do_mount_proc = BOOL_FALSE("mount_proc");
	int do_systemd_hack = BOOL_FALSE("systemd");
	int do_alt_root_symlinks = BOOL_FALSE("root_symlink_usr");
	uint64_t rootfs_opts = ctrtool_options_parse_arg_int_with_preset(get_arg("root_link_opts"), root_link_opts, CTRTOOL_ARRAY_SIZE(root_link_opts), "Invalid root_link_opts", 0xaaaaaaaa);
	uint64_t dev_opts = ctrtool_options_parse_arg_int_with_preset(get_arg("dev_opts"), devfs_opts, CTRTOOL_ARRAY_SIZE(devfs_opts), "Invalid dev_opts", 0xaaaaaaaa);
	check_syscall(umask(ctrtool_options_parse_arg_int(get_arg("umask"), "Invalid umask", NULL, 022)), "umask");
	
	char *mount_proc_s = ctrtool_options_get_arg("pid_ns");
	int proc_fd = -1;
	if (mount_proc_s) {
		proc_fd = check_syscall(open(mount_proc_s, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC), "PID namespace");
	} else if (do_mount_proc) {
		proc_fd = -2;
	}
	check_syscall(mount("/dev/null", mount_directory, "tmpfs", 0, get_arg_default(get_arg("tmpfs_mount_opts"), "mode=0755")), "mount tmpfs");
	check_syscall(chdir(mount_directory), "cd mount directory");
	free(mount_directory);
	mount_directory = NULL;
	check_syscall(mkdir("proc", 0700), "mkdir /proc");
	if (proc_fd >= 0) {
		check_syscall(mount_proc(proc_fd, "proc"), "mount /proc");
		close(proc_fd);
	} else if (proc_fd == -2) {
		check_syscall(mount("none", "proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL), "mount /proc");
	}
	check_syscall(mkdir("sys", 0700), "mkdir /sys");
	check_syscall(mkdir("dev", 0777), "mkdir /dev");
	if (do_systemd_hack) {
		check_syscall(mount("dev", "dev", NULL, MS_BIND, NULL), "mount /dev");
	}
	check_syscall(mkdir("dev/net", 0777), "mkdir /dev/net");
	check_syscall(mkdir("dev/mqueue", 0700), "mkdir /dev/mqueue");
	check_syscall(mkdir("dev/pts", 0700), "mkdir /dev/pts");
	check_syscall(mkdir("run", 0777), "mkdir /run");
	if (do_systemd_hack) {
		check_syscall(mount("run", "run", NULL, MS_BIND, NULL), "mount /run");
	}
	if (do_run_dirs) {
		check_syscall(mkdir("run/lock", 0777), "mkdir /run/lock");
		if (do_systemd_hack) {
			check_syscall(mkdir("dev/shm", 0777), "mkdir /dev/shm");
			check_syscall(symlink("/dev/shm", "run/shm"), "/run/shm");
		} else {
			check_syscall(mkdir("run/shm", 0777), "mkdir /run/shm");
			check_syscall(symlink("/run/shm", "dev/shm"), "/dev/shm");
		}
		if (do_tmp_world) {
			check_syscall(chmod("run/lock", 01777), "chmod /run/lock");
			if (do_systemd_hack) {
				check_syscall(chmod("dev/shm", 01777), "chmod /dev/shm");
			} else {
				check_syscall(chmod("run/shm", 01777), "chmod /run/shm");
			}
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
	const char *dev_symlinks[] = {"/dev/full", "/dev/null", "/dev/random", "/dev/tty", "/dev/urandom", "/dev/zero", "/dev/net/tun"};
	const char *dev_symlinks_c[] = {"_host/full", "_host/null", "_host/random", "_host/tty", "_host/urandom", "_host/zero", "../_host/net/tun"};
	for (int i = 0; i < 7; i++) {
		const char *my_value = dev_symlinks[i];
		uint8_t my_opt = (dev_opts >> (2 * i)) & 3;
		switch(my_opt) {
			case 0:
				break;
			case 1:
				check_syscall(symlink(dev_symlinks_c[i], &my_value[1]), "symlink");
				break;
			case 2:
				check_syscall(mknod(&my_value[1], S_IFSOCK|0666, 0), "mknod");
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
