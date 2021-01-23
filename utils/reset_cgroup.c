#define _GNU_SOURCE
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
void write_cgroup(int base_fd, const char *controller_name, const char *path) {
	char buf[PATH_MAX+1] = {0};
	if (snprintf(buf, sizeof(buf)-1, "./%s/%s/cgroup.procs", controller_name, path) <= 0) abort();
	int write_fd = openat(base_fd, buf, O_WRONLY|O_TRUNC|O_NONBLOCK|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW, 0);
	if (write_fd < 0) {
		perror(buf);
		exit(1);
	}
	if (write(write_fd, "0", 1) != 1) {
		perror(buf);
		exit(1);
	}
	close(write_fd);
}
int main(int argc, char **argv) {
	const char *base_path = "/sys/fs/cgroup";
	const char *controllers = "blkio,cpu,devices,freezer,memory,perf_event,pids,rdma";
	const char *addl_controllers = NULL;
	const char *path = ".";
	int opt = 0;
	int do_systemd = 0;
	int do_unified = 0;
	while ((opt = getopt(argc, argv, "+a:b:c:p:su")) >= 0) {
		switch(opt) {
			case 'a':
				addl_controllers = optarg;
				break;
			case 'b':
				base_path = optarg;
				break;
			case 'c':
				controllers = optarg;
				break;
			case 'p':
				path = optarg;
				break;
			case 's':
				do_systemd = 1;
				break;
			case 'u':
				do_unified = 1;
				break;
			default:
				fprintf(stderr, "Usage: %s [-b /sys/fs/cgroup] [-c blkio,cpu,devices,...]\n\t[-p cgroup path] [-s (systemd)] [-u (unified)]\n", argv[0]);
				return 1;
				break;
		}
	}
	char *program_name = argv[optind];
	if (!program_name) {
		fprintf(stderr, "%s: command required\n", argv[0]);
		return 1;
	}
	int base_fd = open(base_path, O_DIRECTORY|O_PATH|O_CLOEXEC|O_RDONLY, 0);
	if (base_fd == -1) {
		perror(base_path);
		return 1;
	}
	char *saveptr = NULL;
	char *controllers_d = strdup(controllers);
	for (char *controller = strtok_r(controllers_d, ",", &saveptr); controller; controller = strtok_r(NULL, ",", &saveptr)) {
		write_cgroup(base_fd, controller, path);
	}
	free(controllers_d);
	if (do_systemd) write_cgroup(base_fd, "systemd", path);
	if (do_unified) write_cgroup(base_fd, "unified", path);
	if (addl_controllers) {
		controllers_d = strdup(addl_controllers);
		for (char *controller = strtok_r(controllers_d, ",", &saveptr); controller; controller = strtok_r(NULL, ",", &saveptr)) {
			write_cgroup(base_fd, controller, path);
		}
		free(controllers_d);
	}
	close(base_fd);
	execvp(argv[optind], &argv[optind]);
	perror("exec");
	return 127;
}
