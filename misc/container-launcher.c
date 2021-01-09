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
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
#include <sched.h>
#include <errno.h>
#include <syscall.h>
struct child_data {
	uint64_t inh_caps;
	uint64_t ambient_caps;
	uint64_t bounding_caps;
	uint32_t securebits;
	uint64_t timerslack_ns;
	uid_t uid;
	gid_t gid;
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

	int notify_parent_fd;
	int wait_fd;
	int log_fd;
	int socketpair_fd;
	int mount_propagation;
	char *pivot_root_dir;
};
struct pid_file {
	char *filename;
	struct pid_file *next;
};
void convert_uint64(const char *str, uint64_t *result) {
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
int make_safe_fd(int new_fd, const char *perror_str, int do_cloexec) {
	if (new_fd == -1) {
		perror(perror_str);
		exit(1);
	}
	int f = fcntl(new_fd, do_cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, 3);
	if (f < 3) abort();
	close(new_fd);
	return f;
}
const char *child_func(struct child_data *data) {
	errno = 0;
	if (data->no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return "prctl";
	}
	/* step 1: setsid() */
	if (data->do_setsid) {
		if (setsid() < 0) return "setsid";
	}
	/* step 1.25: clear env variables */
	if (data->clear_env && !!clearenv()) return "clearenv";
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
	}

	if (data->make_cgroup) {
		if (unshare(CLONE_NEWCGROUP)) return "CLONE_NEWCGROUP";
	}

	/* step 4: set capabilities */
	struct __user_cap_header_struct cap_h = {_LINUX_CAPABILITY_VERSION_3, 0};
	struct __user_cap_data_struct cap_d[2] = {{0}};
	if (syscall(SYS_capget, &cap_h, (cap_user_data_t) &cap_d)) return "capget";
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

	if (syscall(SYS_capset, &cap_h, (cap_user_data_t) &cap_d)) return "capset";

	/* step 5: change uid/gid with keepcaps enabled */
	if (!data->no_setgroups && setgroups(0, NULL)) return "setgroups";
	if (!data->no_uidgid) {
		if ((data->set_inheritable || data->keepcaps) && prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) return "PR_SET_KEEPCAPS";
		if (setresgid(data->gid, data->gid, data->gid)) return "setgid";
		if (setresuid(data->uid, data->uid, data->uid)) return "setuid";
		/* setuid clears effective set but not permitted, try to restore those capabilities if possible */
		if (data->set_inheritable || data->keepcaps) {
			if (syscall(SYS_capset, &cap_h, (cap_user_data_t) &cap_d)) return "capset";
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
			if ((r == -1) && (errno == EINVAL)) break;
			if (r == -1) return "PR_CAPBSET_READ";
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
		if (chdir(data->pivot_root_dir)) return "cd pivot_root_dir";
		/* EVERYTHING BELOW HERE IS ASSUMED TO BE EXTREMELY DANGEROUS SINCE THE ROOT FS HAS CHANGED */
		/* AND A MALICIOUS CONTAINER ROOTFS COULD ALLOW ACCESS TO THE HOST'S ROOT FS */
		/* (ref: https://nvd.nist.gov/vuln/detail/CVE-2019-14271) */
		if (syscall(SYS_pivot_root, ".", ".")) return "!pivot_root";
	}
	/* step 10: mount /proc */
	if ((data->mount_proc & 1) && syscall(SYS_mount, "none", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)) return "!mount /proc";

	/* step 11: umount old root */
	if (data->pivot_root_dir) {
		if (syscall(SYS_umount2, ".", MNT_DETACH)) return "!umount -l .";
	}

	if (data->socketpair_fd >= 0) {
		char buf[40] = {0};
		if (snprintf(buf, sizeof(buf), "%d", data->socketpair_fd) <= 0) return "!snprintf";
		if (setenv("CONTAINER_LAUNCHER_UNIX_FD", buf, 1)) return "!setenv";
	}

	/* step 12: redirect stderr/stdout */
	if (data->log_fd != -1) {
		if (syscall(SYS_dup2, data->log_fd, 1) != 1) return "!dup2";
		if (syscall(SYS_dup2, data->log_fd, 2) != 2) return "!dup2";
		close(data->log_fd);
	}
	return NULL;
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
	uint64_t clone_flags = 0;
	uint64_t uid = 0;
	uint64_t gid = 0;
	int do_wait = 0;
	char *script_file = NULL;
	struct child_data data_to_process = {0};
	data_to_process.log_fd = -1;
	data_to_process.mount_propagation = 0;
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
	struct pid_file *pidfile_list = NULL;
	int do_exec_script = 0;
	/* TODO: long options */
	while ((opt = getopt(argc, argv, "+CimnpUuS:G:gNswx:I:ka:b:f:B:O:tER:L:H:X:de:r:VM:K:P:FDQ:v:q")) >= 0) {
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
				script_file = strdup(optarg);
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
				logfile = strdup(optarg);
				if (logfile == NULL) exit(1);
				break;
			case 'H':
				free(hostname);
				hostname = strdup(optarg);
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
				command_shell = strdup(optarg);
				if (command_shell == NULL) exit(1);
				break;
			case 'r':
				free(data_to_process.pivot_root_dir);
				data_to_process.pivot_root_dir = strdup(optarg);
				if (data_to_process.pivot_root_dir == NULL) exit(1);
				break;
			case 'V':
				data_to_process.clear_env = 1;
				break;
			case 'M':
				free(emptyfile);
				emptyfile = strdup(optarg);
				if (emptyfile == NULL) exit(1);
				break;
			case 'K':
				free(lockfile);
				lockfile = strdup(optarg);
				if (lockfile == NULL) exit(1);
				break;
			case 'P':
				;struct pid_file *new_pidfile = calloc(sizeof(struct pid_file), 1);
				new_pidfile->filename = strdup(optarg);
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
	}
	if ((userns_fd == -2) || (userns_fd >= 0)) {
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
		data_to_process.mount_propagation = ((clone_flags & CLONE_NEWNS) || (userns_fd >= 0)) ? mount_propagation : 0;
		data_to_process.socketpair_fd = -1;
		data_to_process.notify_parent_fd = -1;
		data_to_process.wait_fd = -1;
		data_to_process.log_fd = -1;
		const char *r = child_func(&data_to_process);
		if (r) {
			if (r[0] == '!') {
				syscall(SYS_write, 2, "some process failed\n", 20);
				_exit(1);
			}
			perror(r);
			exit(1);
		}
		execvp(argv[optind], &argv[optind]);
		exit(127);
		return 127;
	}
	int lockfile_fd = -1;
	if (lockfile) {
		lockfile_fd = open(lockfile, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
		if (lockfile_fd == -1) {
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
	int pipe_to_child[2] = {-1, -1};
	int pipe_from_child[2] = {-1, -1};
	int socketpair_to_child[2] = {-1, -1};
	if (pipe2(pipe_to_child, O_CLOEXEC)) return 1;
	if (pipe2(pipe_from_child, O_CLOEXEC)) return 1;
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
	int log_fd = -1;
	if (logfile) {
		log_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0600);
		if (log_fd == -1) {
			perror(logfile);
			return 1;
		}
	}
	free(logfile); logfile = NULL;
	uid_t current_uids[3] = {0, 0, 0};
	if (owner_uid != -1) {
		if (getresuid(&current_uids[0], &current_uids[1], &current_uids[2])) return 1;
		current_uids[2] = current_uids[1];
		current_uids[1] = owner_uid;
		if (setresuid(current_uids[0], current_uids[1], current_uids[2])) {
			perror("setresuid");
			return 1;
		}
	}
	/* TODO: clone3, int $0x80 on x86 */
	long clone_result = syscall(SYS_clone, clone_flags|SIGCHLD, 0, 0, 0, 0);
	if (clone_result < 0) {
		perror("clone()");
		return 1;
	}
	if (clone_result == 0) {
		if (hostname) {
			if (sethostname(hostname, strlen(hostname))) {
				perror("sethostname");
				_exit(1);
			}
		}
		close(pipe_to_child[1]);
		close(pipe_from_child[0]);
		close(socketpair_to_child[0]);
		close(lockfile_fd);
		data_to_process.mount_propagation = mount_propagation;
		data_to_process.socketpair_fd = socketpair_to_child[1];
		data_to_process.notify_parent_fd = pipe_from_child[1];
		data_to_process.wait_fd = pipe_to_child[0];
		data_to_process.log_fd = log_fd;
		const char *r = child_func(&data_to_process);
		if (r) {
			if (r[0] == '!') {
				syscall(SYS_write, 2, "some process failed\n", 20);
				_exit(1);
			}
			perror(r);
			_exit(1);
		}
		execvp(argv[optind], &argv[optind]);
		_exit(127);
		return 127;
	}
	close(pipe_to_child[0]);
	close(pipe_from_child[1]);
	close(socketpair_to_child[1]);
	if (owner_uid != -1) {
		current_uids[1] = current_uids[2];
		if (setresuid(current_uids[0], current_uids[1], current_uids[2])) {
			perror("setresuid");
			return 1;
		}
	}
	char c_buf1[100] = {0};
	char c_buf2[100] = {0};
	char c_buf3[100] = {0};
	char c_buf4[100] = {0};
	char c_buf5[100] = {0};
	if (snprintf(c_buf1, sizeof(c_buf1), "/proc/%lu", clone_result) <= 0) return 1;
	int proc_pid_dir = open(c_buf1, O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
	if (proc_pid_dir == -1) {
		perror("open /proc/pid");
		return 1;
	}
	if (snprintf(c_buf2, sizeof(c_buf2), "%d", proc_pid_dir) <= 0) return 1;
	if (snprintf(c_buf3, sizeof(c_buf3), "%d", socketpair_to_child[0]) <= 0) return 1;
	if (snprintf(c_buf4, sizeof(c_buf4), "%d", lockfile_fd) <= 0) return 1;
	if (snprintf(c_buf5, sizeof(c_buf5), "%d", pipe_to_child[1]) <= 0) return 1;

	/* step 1: wait for process to be ready */
	char buf = 0;
	if (read(pipe_from_child[0], &buf, 1) != 1) {
		perror("child exited?");
		return 1;
	}
	close(pipe_from_child[0]);
	/* emptyfile */
	if (emptyfile) {
		int emptyfile_fd = open(emptyfile, O_RDONLY|O_CLOEXEC);
		if (emptyfile_fd == -1) {
			perror(emptyfile);
			return 1;
		}
		char buf[512] = {0};
		if (read(emptyfile_fd, buf, 512)) {
			fputs("emptyfile is not empty\n", stderr);
			return 1;
		}
		close(emptyfile_fd);
	}
	const char *pid_string = &c_buf1[6];
	size_t pid_strlen = strlen(pid_string);
	for (struct pid_file *in_pid = pidfile_list; in_pid;) {
		int my_file = open(in_pid->filename, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC);
		if (my_file == -1) {
			perror(in_pid->filename);
			return 1;
		}
		if (write(my_file, pid_string, pid_strlen) != pid_strlen) {
			perror(in_pid->filename);
			return 1;
		}
		close(my_file);
		struct pid_file *next = in_pid->next;
		free(in_pid->filename);
		free(in_pid);
		in_pid = next;
	}
	if (do_exec_script) {
		if (!script_file) {
			return 0;
		}
		if (lockfile_fd != -1) {
			int fl = fcntl(lockfile_fd, F_GETFD);
			if (fl == -1) return 1;
			if (fcntl(lockfile_fd, F_SETFD, ~(FD_CLOEXEC) & fl)) return 1;
		}
		if (pipe_to_child[1] != -1) {
			int fl = fcntl(pipe_to_child[1], F_GETFD);
			if (fl == -1) return 1;
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
		if (script_pid == -1) {
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
			if ((wait_for_pid == -1) && (errno == EINTR)) continue;
			return 1;
		}
		int my_exit_status = 127;
		if (WIFEXITED(wait_status) && ((my_exit_status = WEXITSTATUS(wait_status)) == 0)) {
		} else {
			return my_exit_status;
		}
	}
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
			if ((wait_for_pid == -1) && (errno == EINTR)) continue;
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
