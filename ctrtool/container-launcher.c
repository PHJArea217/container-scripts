#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <linux/capability.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <sys/file.h>
#include <wait.h>
#include <sys/mount.h>
#include <ctype.h>
#include <grp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
#include <sched.h>
#include <linux/sched.h>
#include <errno.h>
#include <getopt.h>
#include <syscall.h>
#include "ctrtool-common.h"
struct child_data {
	uint64_t inh_caps;
	uint64_t ambient_caps;
	uint64_t bounding_caps;
	uint32_t securebits;
	uint64_t timerslack_ns;
	uid_t uid;
	gid_t gid;
	struct iovec supp_groups;
	unsigned no_setgroups:1;
	unsigned no_uidgid:1;
	unsigned do_setsid:1;
	unsigned inh_all:1;
	unsigned inh_ambient:1;
	unsigned set_bounding:1;
	unsigned mount_proc:1;
	unsigned set_securebits:1;
	unsigned set_inheritable:1;
	unsigned clear_env:1;
	unsigned make_cgroup:1;
	unsigned no_new_privs:1;
	unsigned set_timerslack:1;
	unsigned set_thp:2;
	unsigned keepcaps:1;
	unsigned no_cloexec_exec_fd:1;
	unsigned exec_fd_is_memfd:1;
	unsigned debug_dumpable:1;
	unsigned fork_mode:2;
	unsigned clear_caps_before_exec:1;

	int notify_parent_fd;
	int wait_fd;
	int log_fd;
	int socketpair_fd;
	int mount_propagation;

	int exec_fd;
	char *exec_file;
	char *pivot_root_dir;
	uint32_t *shared_mem_region;
	struct ctrtool_arraylist close_fds;
};
struct pid_file {
	char *filename;
	struct pid_file *next;
};
#define NSENTER_REQUESTS_MAX 64
static char *nsenter_requests[NSENTER_REQUESTS_MAX] = {0};
static char *nsenter_post_requests[NSENTER_REQUESTS_MAX] = {0};
static void convert_uint64(const char *str, uint64_t *result) {
	if (!isdigit(str[0])) {
		fprintf(stderr, "Invalid number: %s\n", str);
		exit(1);
	}
	errno = 0;
	unsigned long long r = strtoull(str, NULL, 0);
	if (errno) {
		fprintf(stderr, "Invalid number: %s\n", str);
		exit(1);
	}
	*result = r;
}
#if 0
static int make_safe_fd(int new_fd, const char *perror_str, int do_cloexec) {
	if (new_fd == -1) {
		perror(perror_str);
		exit(1);
	}
	int f = fcntl(new_fd, do_cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, 3);
	if (f < 3) abort();
	close(new_fd);
	return f;
}
#endif
static const char *child_func(struct child_data *data, int *errno_ptr) {
	errno = 0;
	if (data->no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return "prctl";
	}
	if (data->close_fds.nr) {
		int *fd_start = data->close_fds.start;
		for (size_t i = 0; i < data->close_fds.nr; i++) {
//			if (fcntl(fd_start[i], F_SETFD, FD_CLOEXEC)) {
//				return "close";
//			}
			if (close(fd_start[i])) {
				return "close";
			}
		}
		free(fd_start);
		data->close_fds.start = NULL;
	}
	/* step 1: setsid() */
	if (data->do_setsid) {
		if (setsid() < 0) return "setsid";
	}
	/* step 1.25: clear env variables */
	if (data->clear_env && !!clearenv()) return "clearenv";
	if (data->socketpair_fd >= 0) {
		char buf[40] = {0};
		if (snprintf(buf, sizeof(buf), "%d", data->socketpair_fd) <= 0) return "snprintf";
		if (setenv("CONTAINER_LAUNCHER_UNIX_FD", buf, 1)) return "setenv";
	}
	/* step 1.4: make the exec file close-on-exec */
	if (data->exec_fd >= 0) {
		if (!data->no_cloexec_exec_fd) {
			int fdflags = fcntl(data->exec_fd, F_GETFD, 0);
			if (fdflags < 0) return "fcntl";
			if (fcntl(data->exec_fd, F_SETFD, fdflags | FD_CLOEXEC)) return "fcntl";
		} else {
			char env_buf[100] = {0};
			if (snprintf(env_buf, sizeof(env_buf), "%d", data->exec_fd) <= 0) {
				return "snprintf";
			}
			if (setenv("CTRTOOL_CONTAINER_LAUNCHER_EXEC_FD", env_buf, 1)) return "setenv";
		}
	}
	/* step 1.5: mount propagation */
	if (data->mount_propagation) {
		if (mount(NULL, "/", NULL, MS_REC|data->mount_propagation, NULL)) return "mount /proc";
	}
	if (data->notify_parent_fd >= 0) {
		/* step 2: notify parent */
		if (write(data->notify_parent_fd, "\0", 1) != 1) return "notify fd";
		close(data->notify_parent_fd);
		/* step 3: wait for script */
		char buf = 0;
		if (read(data->wait_fd, &buf, 1) != 1) return "notify fd";
		close(data->wait_fd);
		__sync_synchronize();
		if (data->shared_mem_region) {
			if (data->shared_mem_region[0] != 123456789) {
				return "notify fd";
			}
		}
	}

	if (data->make_cgroup) {
		if (unshare(CLONE_NEWCGROUP)) return "CLONE_NEWCGROUP";
	}

	/* Seal the executable file, if we used memfd */
	if (data->exec_fd_is_memfd) {
		if (fcntl(data->exec_fd, F_ADD_SEALS, F_SEAL_SEAL|F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW)) {
			return "F_ADD_SEALS";
		}
		/* Rewind back to the starting position, so that in a common case where the script writes
		 * to the memfd directly, we don't instantly see EOF.
		 */
		if (lseek(data->exec_fd, 0, SEEK_SET)) {
			return "lseek";
		}
	}

	/* step 4: set capabilities */
	struct __user_cap_header_struct cap_h = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct cap_d[2] = {{0}};
	if (ctrtool_syscall_errno(SYS_capget, errno_ptr, &cap_h, (cap_user_data_t) &cap_d, 0, 0, 0, 0)) return "capget";
	uint64_t current_permitted = ((uint64_t) cap_d[1].permitted) << 32 | ((uint64_t) cap_d[0].permitted);
	uint64_t current_inheritable = ((uint64_t) cap_d[1].inheritable) << 32 | ((uint64_t) cap_d[0].inheritable);
	
	/* Enable all inheritable capabilities, also set effective to permitted */
	if (data->set_inheritable) {
		current_inheritable = data->inh_all ? (current_inheritable | current_permitted) : data->inh_caps;
	}
	cap_d[1].inheritable = current_inheritable >> 32;
	cap_d[0].inheritable = current_inheritable & 0xffffffff;
	cap_d[1].effective = cap_d[1].permitted;
	cap_d[0].effective = cap_d[0].permitted;
	cap_h.version = _LINUX_CAPABILITY_VERSION_3;
	cap_h.pid = 0;

	if (ctrtool_syscall_errno(SYS_capset, errno_ptr, &cap_h, (cap_user_data_t) &cap_d, 0, 0, 0, 0)) return "capset";

	/* step 5: change uid/gid with keepcaps enabled */
	if (!data->no_setgroups && setgroups(data->supp_groups.iov_len, (gid_t *) data->supp_groups.iov_base)) return "setgroups";
	free(data->supp_groups.iov_base);
	data->supp_groups.iov_base = NULL;
	data->supp_groups.iov_len = 0;
	if (!data->no_uidgid) {
		if ((data->set_inheritable || data->keepcaps) && prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) return "PR_SET_KEEPCAPS";
		if (setresgid(data->gid, data->gid, data->gid)) return "setgid";
		if (setresuid(data->uid, data->uid, data->uid)) return "setuid";
		/* setuid clears effective set but not permitted, try to restore those capabilities if possible */
		if (data->set_inheritable || data->keepcaps) {
			if (ctrtool_syscall_errno(SYS_capset, errno_ptr, &cap_h, (cap_user_data_t) &cap_d, 0, 0, 0, 0)) return "capset";
		}
	}

	/* step 6: change ambient capabilities */
	uint64_t ambient_caps = data->inh_ambient ? current_inheritable : data->ambient_caps;
	for (int i = 0; i < 64; i++) {
		if (ambient_caps & (1ULL << i)) {
			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0)) return "PR_CAP_AMBIENT_RAISE";
		}
	}

	/* step 7: clear bounding set */
	if (data->set_bounding) {
		for (int i = 0; i < 64; i++) {
			int r = prctl(PR_CAPBSET_READ, i, 0, 0, 0);
			if ((r < 0) && (errno == EINVAL)) break;
			if (r < 0) return "PR_CAPBSET_READ";
			if (r == 1) {
				if (!(data->bounding_caps & (1ULL << i))) {
					if (prctl(PR_CAPBSET_DROP, i, 0, 0, 0)) return "PR_CAPBSET_DROP";
				}
			}
			if (r == 0) {
				if (data->bounding_caps & (1ULL << i)) {
					fprintf(stderr, "Capability %d not in bounding set\n", i);
					return "!";
				}
			}
		}
	}

	/* step 8: set securebits */
	if (data->set_securebits && prctl(PR_SET_SECUREBITS, data->securebits, 0, 0, 0)) return "PR_SET_SECUREBITS";

	if (data->set_thp) {
		if (prctl(PR_SET_THP_DISABLE, !!(data->set_thp == 1), 0, 0, 0)) {
			return "PR_SET_THP_DISABLE";
		}
	}
	if (data->set_timerslack) {
		if (prctl(PR_SET_TIMERSLACK, data->timerslack_ns, 0, 0, 0)) {
			return "PR_SET_TIMERSLACK";
		}
	}

	/* step 8.5: open /dev/null as stdin */
	if (data->log_fd != -1) {
		int devnull_fd = open("/dev/null", O_RDONLY);
		if (devnull_fd < 0) return "open /dev/null";
		if ((devnull_fd > 0) && dup2(devnull_fd, 0)) return "dup2 /dev/null";
		if (devnull_fd > 0) close(devnull_fd);
	}
	/* step 9: pivot_root */
	if (data->pivot_root_dir) {
		if (!data->debug_dumpable) {
			if (ctrtool_syscall_errno(SYS_prctl, errno_ptr, PR_SET_DUMPABLE, 0, 0, 0, 0, 0)) {
				return "!PR_SET_DUMPABLE";
			}
		}
		if (chdir(data->pivot_root_dir)) return "cd pivot_root_dir";
		/* EVERYTHING BELOW HERE IS ASSUMED TO BE EXTREMELY DANGEROUS SINCE THE ROOT FS HAS CHANGED */
		/* AND A MALICIOUS CONTAINER ROOTFS COULD ALLOW ACCESS TO THE HOST'S ROOT FS */
		/* (ref: https://nvd.nist.gov/vuln/detail/CVE-2019-14271) */
		if (ctrtool_syscall_errno(SYS_pivot_root, errno_ptr, ".", ".", 0, 0, 0, 0)) return "!pivot_root";
	}
	/* step 10: mount /proc */
	if ((data->mount_proc & 1) && ctrtool_syscall_errno(SYS_mount, errno_ptr, "none", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL, 0)) return "!mount /proc";

	/* step 11: umount old root */
	if (data->pivot_root_dir) {
		if (ctrtool_syscall_errno(SYS_umount2, errno_ptr, ".", MNT_DETACH, 0, 0, 0, 0)) return "!umount -l .";
	}
	/* step 11.5: process nsenter post requests */
	for (int i = 0; i < NSENTER_REQUESTS_MAX; i++) {
		if (!nsenter_post_requests[i]) break;
		switch (cl_nsenter_params(nsenter_post_requests[i], errno_ptr, 0)) {
			case 0:
				break;
			case -2:
				return "!cannot read nsenter argument";
				break;
			default:
				return "!nsenter failed";
				break;
		}
	}
	if (!data->debug_dumpable) {
		if (ctrtool_syscall_errno(SYS_prctl, errno_ptr, PR_SET_DUMPABLE, 0, 0, 0, 0, 0)) {
			return "!PR_SET_DUMPABLE";
		}
	}

	if (data->clear_caps_before_exec) {
		if (ctrtool_prepare_caps_for_exec(errno_ptr)) return "!ctrtool_prepare_caps_for_exec";
	}
	/* step 12: redirect stderr/stdout */
	if (data->log_fd != -1) {
		if (ctrtool_syscall_errno(SYS_dup3, errno_ptr, data->log_fd, 1, 0, 0, 0, 0) != 1) return "!dup3";
		if (ctrtool_syscall_errno(SYS_dup3, errno_ptr, data->log_fd, 2, 0, 0, 0, 0) != 2) return "!dup3";
		ctrtool_syscall_errno(SYS_close, errno_ptr, data->log_fd, 0, 0, 0, 0, 0);
	}
	/* step 13: fork mode */
	if (data->fork_mode) {
		pid_t child_pid = ctrtool_clone_onearg(SIGCHLD);
		if (child_pid < 0) {
			*errno_ptr = -child_pid;
			return "!fork";
		} else if (child_pid == 0) {
			return NULL;
		}
		if (data->fork_mode == 2) {
			ctrtool_exit(0);
		}
start_wait:;
	   	int wait_status = 0;
		if (ctrtool_syscall_errno(SYS_wait4, errno_ptr, child_pid, &wait_status, 0, 0, 0, 0) != child_pid) {
			if (*errno_ptr == EINTR) goto start_wait;
		}
		ctrtool_exit(WIFEXITED(wait_status) ? WEXITSTATUS(wait_status) : (WIFSIGNALED(wait_status) ? (128 + WTERMSIG(wait_status)) : 255));
	}
	return NULL;
}
int ctr_scripts_container_launcher_main(int argc, char **argv) {
	/* trigger malloc init right now */
	free(malloc(1));
	errno = 0;
	uint64_t clone_flags = 0;
	uint64_t uid = 0;
	uint64_t gid = 0;
	int do_wait = 0;
	char *script_file = NULL;
	struct child_data data_to_process = {0};
	data_to_process.log_fd = -1;
	data_to_process.exec_fd = -1;
	data_to_process.mount_propagation = 0;
	data_to_process.close_fds.elem_size = sizeof(int);
	int mount_propagation = MS_BIND; /* a nonsensical value */
	int userns_fd = -1;
	uid_t owner_uid = -1;
	int mount_proc = 0; /* 0 = normal, 1 = safe, 2 = unsafe */
	char *logfile = NULL;
	char *hostname = NULL;
	unsigned int unix_socket_mode = 0; /* 1 = stream, 2 = dgram, 3 = seqpacket */
	int command_mode = 0;
	char *command_shell = NULL;
	int opt = 0;
	char *emptyfile = NULL;
	char *lockfile = NULL;
	char *exec_file = NULL;
	struct pid_file *pidfile_list = NULL;
	int do_exec_script = 0;
	char *uid_map_str = NULL;
	size_t uid_map_strlen = 0;
	char *gid_map_str = NULL;
	size_t gid_map_strlen = 0;
	int deny_setgroups = 0;
	int do_pidfd = 0;
	int errno_ptr = 0;
	size_t current_nsenter_point = 0;
	size_t current_nsenter_post_point = 0;
	struct iovec clone3_set_tid = {0};
	struct ctrtool_arraylist rlimit_list = {0};
	rlimit_list.elem_size = sizeof(struct ctrtool_rlimit);
	int has_escaped = 0;
	int unsafe_no_escape = 0;
	int clear_caps_before_exec = 2;
	int clear_caps_before_exec_default = 0;
	static struct option long_options[] = {
		{"ambient-caps", required_argument, NULL, 'a'},
		{"bounding-caps", required_argument, NULL, 'b'},
		{"cgroup", no_argument, NULL, 'C'},
		{"clear-caps-before-exec", optional_argument, NULL, 70019},
		{"clearenv", no_argument, NULL, 'V'},
		{"close-fd", required_argument, NULL, 70013},
		{"disable-setgroups", no_argument, NULL, 70006},
		{"emptyfile", required_argument, NULL, 'M'},
		{"exec-anon-fd", no_argument, NULL, 70008},
		{"exec-fd", required_argument, NULL, 70000},
		{"exec-file", required_argument, NULL, 70001},
		{"exec-file-host", required_argument, NULL, 70002},
		{"exec-no-cloexec", no_argument, NULL, 70003},
		{"escape", no_argument, NULL, 70016},
		{"fork", no_argument, NULL, 70011},
		{"fork-daemon", no_argument, NULL, 70012},
		{"gid", required_argument, NULL, 'G'},
		{"gid-map", required_argument, NULL, 70005},
		{"groups", required_argument, NULL, 70100},
		{"hostname", required_argument, NULL, 'H'},
		{"inh-caps", required_argument, NULL, 'I'},
		{"ipc", no_argument, NULL, 'i'},
		{"inh-all", no_argument, NULL, 'k'},
		{"keepcaps", no_argument, NULL, 'q'},
		{"lockfile", required_argument, NULL, 'K'},
		{"log-file", required_argument, NULL, 'L'},
		{"mount", no_argument, NULL, 'm'},
		{"mount-proc", no_argument, NULL, 't'},
		{"net", no_argument, NULL, 'n'},
		{"nsenter", required_argument, NULL, 70009},
		{"nsenter-post", required_argument, NULL, 70010},
		{"no-clear-groups", no_argument, NULL, 'g'},
		{"no-new-privs", no_argument, NULL, 'D'},
		{"no-set-id", no_argument, NULL, 'N'},
		{"owner-uid", required_argument, NULL, 'O'},
		{"pid", no_argument, NULL, 'p'},
		{"pidfd", no_argument, NULL, 70007},
		{"pivot-root", required_argument, NULL, 'r'},
		{"propagation", required_argument, NULL, 'R'},
		{"rlimit", required_argument, NULL, 70015},
		{"script", required_argument, NULL, 'x'},
		{"script-interpreter", required_argument, NULL, 'e'},
		{"script-is-shell", no_argument, NULL, 'd'},
		{"script-no-fork", no_argument, NULL, 'F'},
		{"securebits", required_argument, NULL, 'B'},
		{"setsid", no_argument, NULL, 's'},
		{"set-tid", required_argument, NULL, 70014},
		{"socketpair", required_argument, NULL, 'X'},
		{"thp-disable", required_argument, NULL, 'v'},
		{"timerslack", required_argument, NULL, 'Q'},
		{"uid", required_argument, NULL, 'S'},
		{"uid-map", required_argument, NULL, 70004},
		{"unsafe", no_argument, NULL, 'E'},
		{"unsafe-debug-dumpable", no_argument, NULL, 70018},
		{"unsafe-no-escape", no_argument, NULL, 70017},
		{"user", no_argument, NULL, 'U'},
		{"userns-fd", required_argument, NULL, 'f'},
		{"uts", no_argument, NULL, 'u'},
		{"wait", no_argument, NULL, 'w'},
		{"write-pid", required_argument, NULL, 'P'},
	};
	while ((opt = getopt_long(argc, argv, "+CimnpUuS:G:gNswx:I:ka:b:f:B:O:tER:L:H:X:de:r:VM:K:P:FDQ:v:q", long_options, NULL)) >= 0) {
		switch(opt) {
			case 'C':
				data_to_process.make_cgroup = 1;
				break;
			case 'i':
				clone_flags |= CLONE_NEWIPC;
				break;
			case 'm':
				clone_flags |= CLONE_NEWNS;
				break;
			case 'n':
				clone_flags |= CLONE_NEWNET;
				break;
			case 'p':
				clone_flags |= CLONE_NEWPID;
				break;
			case 'U':
				clear_caps_before_exec_default = 1;
				clone_flags |= CLONE_NEWUSER;
				break;
			case 'u':
				clone_flags |= CLONE_NEWUTS;
				break;
			case 'S':
				convert_uint64(optarg, &uid);
				data_to_process.uid = uid;
				break;
			case 'G':
				convert_uint64(optarg, &gid);
				data_to_process.gid = gid;
				break;
			case 'g':
				data_to_process.no_setgroups = 1;
				break;
			case 'N':
				data_to_process.no_uidgid = 1;
				break;
			case 's':
				data_to_process.do_setsid = 1;
				break;
			case 'w':
				do_wait = 1;
				break;
			case 'x':
				free(script_file);
				script_file = ctrtool_strdup(optarg);
				if (script_file == NULL) exit(1);
				break;
			case 'I':
				convert_uint64(optarg, &data_to_process.inh_caps);
				data_to_process.set_inheritable = 1;
				break;
			case 'k':
				data_to_process.set_inheritable = 1;
				data_to_process.inh_all = 1;
				break;
			case 'a':
				if (strcmp(optarg, "inherit") == 0) {
					data_to_process.inh_ambient = 1;
				} else {
					convert_uint64(optarg, &data_to_process.ambient_caps);
				}
				break;
			case 'b':
				clear_caps_before_exec_default = 1;
				convert_uint64(optarg, &data_to_process.bounding_caps);
				data_to_process.set_bounding = 1;
				break;
				/* FIXME: allow direct execution without setting userns */
			case 'f':
				if (optarg[0] == 'i') {
					userns_fd = -2;
					break;
				}
				uint64_t userns_fd64 = -1;
				convert_uint64(optarg, &userns_fd64);
				if (userns_fd64 > INT_MAX) {
					fputs("userns fd out of range\n", stderr);
					return 1;
				}
				clear_caps_before_exec_default = 1;
				userns_fd = userns_fd64;
				break;
			case 'B':
				;uint64_t securebits_64 = -1;
				convert_uint64(optarg, &securebits_64);
				data_to_process.securebits = securebits_64;
				data_to_process.set_securebits = 1;
				break;
			case 'O':
				;uint64_t owner_uid_64 = -1;
				convert_uint64(optarg, &owner_uid_64);
				owner_uid = owner_uid_64;
				break;
			case 't':
				mount_proc |= 1;
				data_to_process.mount_proc = 1;
				break;
			case 'E':
				mount_proc |= 2;
				break;
			case 'R':
				switch(optarg[0]) {
					case 's':
						switch(optarg[1]) {
							case 'h': mount_propagation = MS_SHARED; break;
							case 'l': mount_propagation = MS_SLAVE; break;
							default: goto invalid_propagation;
						}
						break;
					case 'p':
						mount_propagation = MS_PRIVATE;
						break;
					case 'u':
						mount_propagation = 0;
						break;
					default:
invalid_propagation:
						fprintf(stderr, "Invalid propagation value %s: should be shared, slave, private, unchanged\n", optarg);
						exit(1);
						break;
				}
				break;
			case 'L':
				free(logfile);
				logfile = ctrtool_strdup(optarg);
				if (logfile == NULL) exit(1);
				break;
			case 'H':
				free(hostname);
				hostname = ctrtool_strdup(optarg);
				if (hostname == NULL) exit(1);
				break;
			case 'X':
				unix_socket_mode = atoi(optarg);
				if (unix_socket_mode > 3) {
					fputs("Invalid option for -X\n", stderr);
					exit(1);
				}
				break;
			case 'd':
				command_mode = 1;
				break;
			case 'e':
				free(command_shell);
				command_shell = ctrtool_strdup(optarg);
				if (command_shell == NULL) exit(1);
				break;
			case 'r':
				clear_caps_before_exec_default = 1;
				free(data_to_process.pivot_root_dir);
				data_to_process.pivot_root_dir = ctrtool_strdup(optarg);
				if (data_to_process.pivot_root_dir == NULL) exit(1);
				break;
			case 'V':
				data_to_process.clear_env = 1;
				break;
			case 'M':
				free(emptyfile);
				emptyfile = ctrtool_strdup(optarg);
				if (emptyfile == NULL) exit(1);
				break;
			case 'K':
				free(lockfile);
				lockfile = ctrtool_strdup(optarg);
				if (lockfile == NULL) exit(1);
				break;
			case 'P':
				;struct pid_file *new_pidfile = calloc(sizeof(struct pid_file), 1);
				new_pidfile->filename = ctrtool_strdup(optarg);
				new_pidfile->next = pidfile_list;
				pidfile_list = new_pidfile;
				break;
			case 'F':
				do_exec_script = 1;
				break;
			case 'D':
				data_to_process.no_new_privs = 1;
				break;
			case 'Q':
				convert_uint64(optarg, &data_to_process.timerslack_ns);
				data_to_process.set_timerslack = 1;
				break;
			case 'v':
				;int thp_option = atoi(optarg);
				data_to_process.set_thp = thp_option ? 1 : 2;
				break;
			case 'q':
				data_to_process.keepcaps = 1;
				break;
			case 70000:
				data_to_process.exec_fd = atoi(optarg);
				break;
			case 70001:
				free(data_to_process.exec_file);
				data_to_process.exec_file = ctrtool_strdup(optarg);
				if (!data_to_process.exec_file) exit(1);
				break;
			case 70002:
				free(exec_file);
				exec_file = ctrtool_strdup(optarg);
				if (!exec_file) exit(1);
				break;
			case 70003:
				data_to_process.no_cloexec_exec_fd = 1;
				break;
			case 70004:
				free(uid_map_str);
				uid_map_str = ctrtool_strdup(optarg);
				if (!uid_map_str) exit(1);
				uid_map_strlen = 0;
				char *uid_map_b = uid_map_str;
				while (*uid_map_b) {
					if (*uid_map_b == ':') *uid_map_b = '\n';
					if (*uid_map_b == '.') *uid_map_b = ' ';
					uid_map_b++;
					uid_map_strlen++;
				}
				break;
			case 70005:
				free(gid_map_str);
				gid_map_str = ctrtool_strdup(optarg);
				if (!gid_map_str) exit(1);
				gid_map_strlen = 0;
				char *gid_map_b = gid_map_str;
				while (*gid_map_b) {
					if (*gid_map_b == ':') *gid_map_b = '\n';
					if (*gid_map_b == '.') *gid_map_b = ' ';
					gid_map_b++;
					gid_map_strlen++;
				}
				break;
			case 70006:
				deny_setgroups = 1;
				break;
			case 70007:
				do_pidfd = 1;
				break;
			case 70008:
				data_to_process.exec_fd = -2;
				break;
			case 70009:
				clear_caps_before_exec_default = 1;
				if (current_nsenter_point >= NSENTER_REQUESTS_MAX) {
					fprintf(stderr, "Maximum of %d nsenter requests are allowed\n", NSENTER_REQUESTS_MAX);
					return 1;
				}
				char *nsenter_request = ctrtool_strdup(optarg);
				if (!nsenter_request) return 1;
				nsenter_requests[current_nsenter_point++] = nsenter_request;
				break;
			case 70010:
				clear_caps_before_exec_default = 1;
				if (current_nsenter_post_point >= NSENTER_REQUESTS_MAX) {
					fprintf(stderr, "Maximum of %d nsenter-post requests are allowed\n", NSENTER_REQUESTS_MAX);
					return 1;
				}
				char *nsenter_post_request = ctrtool_strdup(optarg);
				if (!nsenter_post_request) return 1;
				nsenter_post_requests[current_nsenter_post_point++] = nsenter_post_request;
				break;
			case 70011:
				clear_caps_before_exec_default = 1;
				data_to_process.fork_mode = 1;
				break;
			case 70012:
				clear_caps_before_exec_default = 1;
				data_to_process.fork_mode = 2;
				break;
			case 70013:
				{
					uint64_t fd_to_close = -1;
					convert_uint64(optarg, &fd_to_close);
					if (fd_to_close > INT_MAX) {
						fputs("Number too large\n", stderr);
						return 1;
					}
					int fd_num = fd_to_close;
					if (fcntl(fd_num, F_GETFD, 0) < 0) {
						perror("fcntl");
						return 1;
					}
					if (ctrtool_arraylist_expand(&data_to_process.close_fds, &fd_num, 10)) {
						perror("ctrtool_arraylist_expand");
						return 1;
					}
				}
				break;
			case 70014:
				free(clone3_set_tid.iov_base);
				if (ctrtool_parse_int_array(optarg, &clone3_set_tid, sizeof(pid_t))) {
					perror("--set-tid ctrtool_parse_int_array");
					return 1;
				}
				break;
			case 70015:
				;
				struct ctrtool_rlimit m_limit = {0};
				if (ctrtool_parse_rlimit(optarg, &m_limit)) {
					perror("ctrtool_parse_rlimit");
					return 1;
				}
				if (ctrtool_arraylist_expand(&rlimit_list, &m_limit, 10)) {
					perror("ctrtool_arraylist_expand");
					return 1;
				}
				break;
			case 70016:
				if (!has_escaped) {
					if (ctrtool_escape()) {
						perror("ctrtool_escape");
						return 1;
					}
				}
				has_escaped = 1;
				break;
			case 70017:
				unsafe_no_escape = 1;
				break;
			case 70018:
				data_to_process.debug_dumpable = 1;
				break;
			case 70019:
				if (optarg) {
					clear_caps_before_exec = !!atoi(optarg);
				} else {
					clear_caps_before_exec = 1;
				}
				break;
			case 70100:
				free(data_to_process.supp_groups.iov_base);
				data_to_process.supp_groups.iov_base = NULL;
				if (ctrtool_parse_int_array(optarg, &data_to_process.supp_groups, sizeof(gid_t))) {
					perror("ctrtool_parse_int_array");
					return 1;
				}
				break;
			default:
				fprintf(stderr, "Usage: %s [-flags] [program] [arguments]\n"
						"-C     new cgroup namespace\n"
						"-i     new ipc namespace\n"
						"-m     new mount namespace\n"
						"-n     new network namespace\n"
						"-p     new pid namespace\n"
						"-U     new user namespace\n"
						"-u     new uts namespace\n"
						"-S uid set uid in namespace (default 0)\n"
						"-G gid set gid in namespace (default 0)\n"
						"-g     don't call setgroups(0, NULL)\n"
						"-N     don't change uid/gid\n"
						"-s     call setsid()\n"
						"-w     wait for container to exit\n"
						"-x file script to execute after creating namespaces, called in\n"
						"        initial namespace context with PID number, /proc/PID\n"
						"        file descriptor number of forked process, and (if present)\n"
						"        unix domain socket descriptor from -X (otherwise -1) as arguments\n"
						"        (hint: use openat() to safely access uid_map and ns/* files)\n"
						"-I n   set inheritable capabilities (described as 64-bit integer of shifted bits)\n"
						"-k     set inheritable capabilities to same as permitted\n"
						"-a n   set ambient capabilities; n may be \"inherit\" to use the inheritable set\n"
						"-b n   set bounding capabilities\n"
						"-f n   don't do normal routine; instead, enter user namespace on fd n\n"
						"-fi    don't do normal routine; instead, like -f n but without setns\n"
						"-B n   set securebits\n"
						"-O n   set owner uid (i.e. the forked process will have this effective UID\n"
						"       relative to the current userns)\n"
						"-t     mount procfs on /proc in container process\n"
						"-E     unsafe mode: allow -T even with mount ns not on slave/private or -H without -u\n"
						"-R val set mount propagation (slave, shared, private, unchanged)\n"
						"-L file log file, container use only\n"
						"-H name set hostname, should be used with -u\n"
						"-X n   create unix socketpair for communication, available on script as third argument\n"
						"       and $CONTAINER_LAUNCHER_UNIX_FD in program\n"
						"       n = 1 for stream, 2 for dgram, 3 for seqpacket\n"
						"       (hint: can pass fd's to container using SCM_RIGHTS)\n"
						"-d     -x script is argument to /bin/sh -c script; use $1, $2, $3 to access arguments\n"
						"-e interp replace /bin/sh with interp in /bin/sh -c script (e.g. python3)\n"
						"-r root pivot_root into a new root directory\n"
						"-V     clear all environment variables in container\n"
						"       ($CONTAINER_LAUNCHER_UNIX_FD from -X preserved)\n"
						"-D     Set NO_NEW_PRIVS\n"
						"-q     Set PR_SET_KEEPCAPS (useful only until exec)\n"
						"-P file write PID of container to this file, may be specified more than once\n"
						"        (intended use: write to cgroup.procs to put the container into a cgroup)\n"
						"-M file file to check for emptiness -- exit if file is not empty\n"
						"        (intended use: cgroup.procs file of a cgroup specified by -P)\n"
						"-K file lock file (will not be inherited to container)\n"
						"-F     exec the script rather than forking it -- script takes two additional arguments:\n"
						"       $4: file descriptor of -K lock (if present, otherwise -1)\n"
						"       $5: notify file descriptor (write at least 1 byte there to indicate success)\n"
						, argv[0]);
				return 1;
				break;
		}
	}
	ctrtool_clear_saved_argv();
	if (clear_caps_before_exec == 2) {
		if (clear_caps_before_exec_default) {
			if (data_to_process.no_new_privs || (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0))) {
				fprintf(stderr,
						"The current configuration of flags would automatically enable the internal\n"
						"clear_caps_before_exec mitigation, but the process would run in NO_NEW_PRIVS\n"
						"mode, which would mean that the capabilities would be cleared. You must set\n"
						"the inheritable capabilities (with -I) in this case to set the container's\n"
						"capabilities, then set --clear-caps-before-exec=1 to acknowledge this message.\n");
				return 1;
			}
		}
		clear_caps_before_exec = clear_caps_before_exec_default;
	}
	data_to_process.clear_caps_before_exec = !!clear_caps_before_exec;
	if (mount_propagation == MS_BIND) {
		mount_propagation = (clone_flags & CLONE_NEWNS) ? MS_SLAVE : 0;
	}
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) return 1;
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return 1;
	}
	if (!(mount_proc & 2)) {
		if (!!hostname && !(clone_flags & CLONE_NEWUTS)) {
			fputs("attempting to set hostname without CLONE_NEWUTS, use -E to override\n", stderr);
			return 1;
		}
		if (!!data_to_process.pivot_root_dir && !(clone_flags & CLONE_NEWNS)) {
			fputs("attempting to pivot_root without CLONE_NEWNS, use -E to override\n", stderr);
			return 1;
		}
		/* FIXME: propagation=unchanged by default if no mount ns */
		if (!!mount_propagation && !(clone_flags & CLONE_NEWNS)) {
			fputs("attempting to set propagation without CLONE_NEWNS, use -E to override\n", stderr);
			return 1;
		}
		if (!!(data_to_process.mount_proc & 1) && (!(clone_flags & CLONE_NEWNS) || !((mount_propagation == MS_PRIVATE) || (mount_propagation == MS_SLAVE)))) {
			fputs("attempting to mount /proc with unsafe propagation or without CLONE_NEWNS, use -E to override\n", stderr);
			return 1;
		}
		if ((userns_fd == -1) && current_nsenter_point) {
			fputs("attempting to use --nsenter without -f, use -E to override\n", stderr);
			return 1;
		}
	}
	if (!unsafe_no_escape) {
		if (!has_escaped) {
			if (current_nsenter_point || current_nsenter_post_point) {
				fputs("attempting to use --nsenter or --nsenter-post without --escape\n", stderr);
				return 1;
			}
			if ((userns_fd >= 0) || (clone_flags & CLONE_NEWUSER)) {
				fputs("attempting to use --user or --userns-fd without --escape\n", stderr);
				return 1;
			}
		}
	}
	if (exec_file) {
		if (data_to_process.exec_fd >= 0) {
			fprintf(stderr, "--exec-file-host and --exec-fd cannot be used together\n");
			return 1;
		}
		data_to_process.exec_fd = open(exec_file, O_RDONLY|O_NOCTTY);
		if (data_to_process.exec_fd < 0) {
			perror("exec_file");
			return 1;
		}
		free(exec_file);
		exec_file = NULL;
	}
	if (data_to_process.exec_fd == -2) {
		data_to_process.exec_fd = memfd_create("", MFD_ALLOW_SEALING);
		if (data_to_process.exec_fd < 0) {
			perror("memfd_create");
			return 1;
		}
		data_to_process.exec_fd_is_memfd = 1;
		if (fchmod(data_to_process.exec_fd, 0755)) {
			return 1;
		}
	}
	if (data_to_process.exec_fd >= 0) {
		char env_buf[100] = {0};
		if (snprintf(env_buf, sizeof(env_buf), "%d", data_to_process.exec_fd) <= 0) {
			return 1;
		}
		if (setenv("CTRTOOL_CONTAINER_LAUNCHER_EXEC_FD", env_buf, 1)) return 1;
	}

	if ((userns_fd <= -2) || (userns_fd >= 0)) {
		/* FIXME: maybe make this optional? */
		if (userns_fd >= 0) {
			if (setns(userns_fd, CLONE_NEWUSER)) {
				perror("setns");
				return 1;
			}
		}
		if (clone_flags) {
			if (unshare(clone_flags)) {
				perror("unshare");
				return 1;
			}
		}
		for (int i = 0; i < NSENTER_REQUESTS_MAX; i++) {
			if (!nsenter_requests[i]) break;
			switch (cl_nsenter_params(nsenter_requests[i], &errno_ptr, 1)) {
				case 0:
					break;
				case -2:
					ctrtool_cheap_perror("cannot read nsenter argument", errno_ptr);
					ctrtool_exit(1);
					break;
				default:
					ctrtool_cheap_perror("nsenter failed", errno_ptr);
					ctrtool_exit(1);
					break;
			}
		}
		data_to_process.mount_propagation = ((clone_flags & CLONE_NEWNS) || (userns_fd >= 0)) ? mount_propagation : 0;
		data_to_process.socketpair_fd = -1;
		data_to_process.notify_parent_fd = -1;
		data_to_process.wait_fd = -1;
		data_to_process.log_fd = -1;
		const char *r = child_func(&data_to_process, &errno_ptr);
		if (r) {
			if (r[0] == '!') {
				ctrtool_cheap_perror(&r[1], errno_ptr);
				_exit(1);
			}
			if (errno_ptr) errno = errno_ptr;
			perror(r);
			exit(1);
		}
		errno_ptr = 0;
		if (data_to_process.exec_fd >= 0) {
			ctrtool_syscall_errno(SYS_execveat, &errno_ptr, data_to_process.exec_fd, "", &argv[optind], environ, AT_EMPTY_PATH, 0);
		} else if (data_to_process.exec_file) {
			ctrtool_syscall_errno(SYS_execve, &errno_ptr, data_to_process.exec_file, &argv[optind], environ, 0, 0, 0);
		} else {
			execvp(argv[optind], &argv[optind]);
			errno_ptr = errno;
		}
		ctrtool_cheap_perror("exec failed", errno_ptr);
		ctrtool_exit(127);
		return 127;
	}
	if (!do_exec_script) {
		data_to_process.shared_mem_region = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
		if ((data_to_process.shared_mem_region == NULL) || (data_to_process.shared_mem_region == MAP_FAILED)) {
			return 1;
		}
	}
	int lockfile_fd = -1;
	if (lockfile) {
		lockfile_fd = open(lockfile, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
		if (lockfile_fd < 0) {
			perror(lockfile);
			return 1;
		}
		if (flock(lockfile_fd, LOCK_EX)) {
			perror(lockfile);
			return 1;
		}
		free(lockfile);
		lockfile = NULL;
	}
	int log_fd = -1;
	if (logfile) {
		log_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0600);
		if (log_fd < 0) {
			perror(logfile);
			return 1;
		}
	}
	free(logfile); logfile = NULL;
	
	int pipe_to_child[2] = {-1, -1};
	int pipe_from_child[2] = {-1, -1};
	if (pipe2(pipe_to_child, O_CLOEXEC)) return 1;
	if (pipe2(pipe_from_child, O_CLOEXEC)) return 1;
	
	uid_t current_uids[3] = {0, 0, 0};
	if (owner_uid != -1) {
		if (getresuid(&current_uids[0], &current_uids[1], &current_uids[2])) return 1;
		current_uids[2] = current_uids[1];
		current_uids[1] = owner_uid;
		if (setresuid(current_uids[0], current_uids[1], current_uids[2])) {
			perror("setresuid");
			return 1;
		}
		if (ctrtool_load_permitted_caps()) {
			perror("ctrtool_load_permitted_caps");
			return 1;
		}
	}
	for (int i = 0; i < NSENTER_REQUESTS_MAX; i++) {
		if (!nsenter_requests[i]) break;
		switch (cl_nsenter_params(nsenter_requests[i], &errno_ptr, 1)) {
			case 0:
				break;
			case -2:
				ctrtool_cheap_perror("cannot read nsenter argument", errno_ptr);
				ctrtool_exit(1);
				break;
			default:
				ctrtool_cheap_perror("nsenter failed", errno_ptr);
				ctrtool_exit(1);
				break;
		}
	}
	int socketpair_to_child[2] = {-1, -1};
	if (unix_socket_mode) {
		int the_type = SOCK_STREAM;
		switch(unix_socket_mode) {
			case 1:
				the_type = SOCK_STREAM;
				break;
			case 2:
				the_type = SOCK_DGRAM;
				break;
			case 3:
				the_type = SOCK_SEQPACKET;
				break;
		}
		if (socketpair(AF_UNIX, the_type, 0, socketpair_to_child)) return 1;
	}
	long clone_result;
	if (clone3_set_tid.iov_len) {
#ifdef CTRTOOL_CLONE3_HACK
		__aligned_u64 clone_args0[10] = {0};
		clone_args0[0] = clone_flags;
		clone_args0[4] = SIGCHLD;
		clone_args0[8] = (uint64_t) clone3_set_tid.iov_base;
		clone_args0[9] = clone3_set_tid.iov_len;
#else
		struct clone_args clone_args0 = {0};
		clone_args0.flags = clone_flags;
		clone_args0.exit_signal = SIGCHLD;
		clone_args0.set_tid = (uint64_t) clone3_set_tid.iov_base;
		clone_args0.set_tid_size = clone3_set_tid.iov_len;
#endif
		clone_result = ctrtool_raw_syscall(SYS_clone3, &clone_args0, sizeof(clone_args0), 0, 0, 0, 0);
	} else {
		clone_result = ctrtool_clone_onearg(clone_flags|SIGCHLD);
	}
	if (clone_result < 0) {
		errno = -clone_result;
		perror("clone()");
		return 1;
	}
	free(clone3_set_tid.iov_base);
	if (clone_result == 0) {
		if (hostname) {
			if (sethostname(hostname, strlen(hostname))) {
				perror("sethostname");
				ctrtool_exit(1);
			}
		}
		close(pipe_to_child[1]);
		close(pipe_from_child[0]);
		close(socketpair_to_child[0]);
		close(lockfile_fd);
		free(rlimit_list.start);
		data_to_process.mount_propagation = mount_propagation;
		data_to_process.socketpair_fd = socketpair_to_child[1];
		data_to_process.notify_parent_fd = pipe_from_child[1];
		data_to_process.wait_fd = pipe_to_child[0];
		data_to_process.log_fd = log_fd;
		const char *r = child_func(&data_to_process, &errno_ptr);
		if (r) {
			if (r[0] == '!') {
				ctrtool_cheap_perror(&r[1], errno_ptr);
				ctrtool_exit(1);
			}
			if (errno_ptr) errno = errno_ptr;
			perror(r);
			ctrtool_exit(1);
		}
		errno_ptr = 0;
		if (data_to_process.exec_fd >= 0) {
			ctrtool_syscall_errno(SYS_execveat, &errno_ptr, data_to_process.exec_fd, "", &argv[optind], environ, AT_EMPTY_PATH, 0);
		} else if (data_to_process.exec_file) {
			ctrtool_syscall_errno(SYS_execve, &errno_ptr, data_to_process.exec_file, &argv[optind], environ, 0, 0, 0);
		} else {
			execvp(argv[optind], &argv[optind]);
			errno_ptr = errno;
		}
		ctrtool_cheap_perror("exec failed", errno_ptr);
		ctrtool_exit(127);
		return 127;
	}
	if (owner_uid != -1) {
		current_uids[1] = current_uids[2];
		if (setresuid(current_uids[0], current_uids[1], current_uids[2])) {
			perror("setresuid");
			return 1;
		}
	}
	free(data_to_process.supp_groups.iov_base);
	data_to_process.supp_groups.iov_base = NULL;
	data_to_process.supp_groups.iov_len = 0;
	free(data_to_process.close_fds.start);
	close(pipe_to_child[0]);
	close(pipe_from_child[1]);
	close(socketpair_to_child[1]);
	char c_buf1[100] = {0};
	char c_buf2[100] = {0};
	char c_buf3[100] = {0};
	char c_buf4[100] = {0};
	char c_buf5[100] = {0};
	if (snprintf(c_buf1, sizeof(c_buf1), "/proc/%lu", clone_result) <= 0) return 1;
	int proc_pid_dir = open(c_buf1, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
	if (proc_pid_dir < 0) {
		perror("open /proc/pid");
		return 1;
	}
	if (snprintf(c_buf2, sizeof(c_buf2), "%d", proc_pid_dir) <= 0) return 1;
	if (snprintf(c_buf3, sizeof(c_buf3), "%d", socketpair_to_child[0]) <= 0) return 1;
	if (snprintf(c_buf4, sizeof(c_buf4), "%d", lockfile_fd) <= 0) return 1;
	if (snprintf(c_buf5, sizeof(c_buf5), "%d", pipe_to_child[1]) <= 0) return 1;
	if (do_pidfd) {
		char c_buf6[100];
#ifdef SYS_pidfd_open
		int pid_fd = syscall(SYS_pidfd_open, clone_result, 0, 0, 0, 0, 0);
#elif defined(__x86_64__) || defined(__i386__)
		int pid_fd = syscall(434, clone_result, 0, 0, 0, 0, 0);
#else
		int pid_fd = -1;
		fprintf(stderr, "pidfd_open not supported with the current kernel headers!\n");
		return 1;
#endif
		if (pid_fd < 0) {
			perror("pidfd_open");
			return 1;
		}
		if (fcntl(pid_fd, F_SETFD, 0)) {
			return 1;
		}
		if (snprintf(c_buf6, sizeof(c_buf6), "%d", pid_fd) <= 0) return 1;
		if (setenv("CTRTOOL_CONTAINER_LAUNCHER_PID_FD", c_buf6, 1)) return 1;
	}

	/* step 1: wait for process to be ready */
	char buf = 0;
	if (read(pipe_from_child[0], &buf, 1) != 1) {
		perror("child exited?");
		return 1;
	}
	close(pipe_from_child[0]);
	/* emptyfile */
	if (emptyfile) {
		errno = 0;
		int emptyfile_fd = open(emptyfile, O_RDONLY|O_CLOEXEC);
		if (emptyfile_fd < 0) {
			if (errno == ESRCH) {
				/* This is if the /proc/PID directory was bind-mounted and the emptyfile was /proc/PID/status or similar. */
				goto no_emptyfile;
			}
			perror(emptyfile);
			return 1;
		}
		char buf[512] = {0};
		if (read(emptyfile_fd, buf, 512)) {
			fputs("emptyfile is not empty\n", stderr);
			return 1;
		}
		close(emptyfile_fd);
no_emptyfile:;
	}
	struct ctrtool_rlimit *rlimit_list_base = rlimit_list.start;
	for (size_t i = 0; i < rlimit_list.nr; i++) {
		struct ctrtool_rlimit *current = &rlimit_list_base[i];
		struct rlimit current_limits = {0};
		if (prlimit(clone_result, current->limit_name, NULL, &current_limits)) {
			perror("prlimit");
			return 1;
		}
		if (current->change_soft) {
			current_limits.rlim_cur = current->limit_value.rlim_cur;
		}
		if (current->change_hard) {
			current_limits.rlim_max = current->limit_value.rlim_max;
		}
		if (prlimit(clone_result, current->limit_name, &current_limits, NULL)) {
			perror("prlimit");
			return 1;
		}
	}
	free(rlimit_list.start);
	const char *pid_string = &c_buf1[6];
	size_t pid_strlen = strlen(pid_string);
	for (struct pid_file *in_pid = pidfile_list; in_pid;) {
		int my_file = open(in_pid->filename, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666);
		if (my_file < 0) {
			perror(in_pid->filename);
			return 1;
		}
		if (write(my_file, pid_string, pid_strlen) != pid_strlen) {
			perror(in_pid->filename);
			return 1;
		}
		if (close(my_file)) {
			perror(in_pid->filename);
			return 1;
		}
		struct pid_file *next = in_pid->next;
		free(in_pid->filename);
		free(in_pid);
		in_pid = next;
	}
	/* write uid/gid maps and deny setgroups */
	if (deny_setgroups) {
		int setgroups_fd = openat(proc_pid_dir, "setgroups", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
		if (setgroups_fd < 0) {
			perror("open /proc/PID/setgroups");
			return 1;
		}
		if (write(setgroups_fd, "deny", 4) != 4) {
			perror("write /proc/PID/setgroups");
			return 1;
		}
		close(setgroups_fd);
	}
	if (uid_map_str) {
		int uid_map_fd = openat(proc_pid_dir, "uid_map", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
		if (uid_map_fd < 0) {
			perror("open /proc/PID/uid_map");
			return 1;
		}
		if (write(uid_map_fd, uid_map_str, uid_map_strlen) != uid_map_strlen) {
			perror("write /proc/PID/uid_map");
			return 1;
		}
		close(uid_map_fd);
	}
	if (gid_map_str) {
		int gid_map_fd = openat(proc_pid_dir, "gid_map", O_WRONLY|O_NONBLOCK|O_CLOEXEC);
		if (gid_map_fd < 0) {
			perror("open /proc/PID/gid_map");
			return 1;
		}
		if (write(gid_map_fd, gid_map_str, gid_map_strlen) != gid_map_strlen) {
			perror("write /proc/PID/gid_map");
			return 1;
		}
		close(gid_map_fd);
	}
	if (do_exec_script) {
		if (!script_file) {
			return 0;
		}
		if (lockfile_fd != -1) {
			int fl = fcntl(lockfile_fd, F_GETFD);
			if (fl < 0) return 1;
			if (fcntl(lockfile_fd, F_SETFD, ~(FD_CLOEXEC) & fl)) return 1;
		}
		if (pipe_to_child[1] != -1) {
			int fl = fcntl(pipe_to_child[1], F_GETFD);
			if (fl < 0) return 1;
			if (fcntl(pipe_to_child[1], F_SETFD, ~(FD_CLOEXEC) & fl)) return 1;
		}
		char *my_argv[] = {script_file, &c_buf1[6], c_buf2, c_buf3, c_buf4, c_buf5, NULL, NULL, NULL, NULL};
		if (command_mode) {
			my_argv[0] = command_shell;
			if (!my_argv[0]) my_argv[0] = "/bin/sh";
			my_argv[1] = "-c";
			my_argv[2] = script_file;
			my_argv[3] = "-";
			my_argv[4] = &c_buf1[6];
			my_argv[5] = c_buf2;
			my_argv[6] = c_buf3;
			my_argv[7] = c_buf4;
			my_argv[8] = c_buf5;
		}
		execvp(my_argv[0], my_argv);
		return 127;
	}
	if (script_file) {
		/* step 2: run the script */
		pid_t script_pid = fork();
		if (script_pid < 0) {
			perror("fork() script");
			return 1;
		}
		if (script_pid == 0) {
			char *my_argv[] = {script_file, &c_buf1[6], c_buf2, c_buf3, NULL, NULL, NULL, NULL};
			if (command_mode) {
				my_argv[0] = command_shell;
				if (!my_argv[0]) my_argv[0] = "/bin/sh";
				my_argv[1] = "-c";
				my_argv[2] = script_file;
				my_argv[3] = "-";
				my_argv[4] = &c_buf1[6];
				my_argv[5] = c_buf2;
				my_argv[6] = c_buf3;
			}
			execvp(my_argv[0], my_argv);
			_exit(127);
		}
		int wait_status = 0;
		while (1) {
			pid_t wait_for_pid = waitpid(script_pid, &wait_status, 0);
			if (wait_for_pid == script_pid) {
				break;
			}
			if ((wait_for_pid < 0) && (errno == EINTR)) continue;
			return 1;
		}
		int my_exit_status = 127;
		if (WIFEXITED(wait_status) && ((my_exit_status = WEXITSTATUS(wait_status)) == 0)) {
		} else {
			return my_exit_status;
		}
	}
	data_to_process.shared_mem_region[0] = 123456789;
	__sync_synchronize();
	munmap(data_to_process.shared_mem_region, 4096);
	buf = 0;
	if (write(pipe_to_child[1], &buf, 1) != 1) {
		perror("child exited?");
		return 1;
	}
	close(pipe_to_child[1]);
	close(socketpair_to_child[0]);
	if (do_wait) {
		int wait_status = 0;
		while (1) {
			pid_t wait_for_pid = waitpid(clone_result, &wait_status, 0);
			if (wait_for_pid == clone_result) {
				break;
			}
			if ((wait_for_pid < 0) && (errno == EINTR)) continue;
			return 1;
		}
		if (WIFEXITED(wait_status)) {
			return WEXITSTATUS(wait_status);
		} else if (WIFSIGNALED(wait_status)) {
			return WTERMSIG(wait_status) + 128;
		} else {
			return 255;
		}
	}
	return 0;
}
