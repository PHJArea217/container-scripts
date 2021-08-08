#include "ctrtool-common.h"
#include <syscall.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
int ctr_scripts_chroot_pivot_main(int argc, char **argv) {
	if (argc<4) {
		fprintf(stderr, "Usage: %s chroot_dir new_root put_old\n", argv[0]);
		return 1;
	}
	int *shared_mem_region = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (shared_mem_region == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	pid_t child_pid = ctrtool_clone_onearg(SIGCHLD);
	if (child_pid == -1) {
		perror("clone()");
		return 1;
	} else if (child_pid == 0) {
		if (ctrtool_syscall_errno(SYS_chroot, shared_mem_region, argv[1], 0, 0, 0, 0, 0)) ctrtool_exit(1);
		if (ctrtool_syscall_errno(SYS_chdir, shared_mem_region, "/", 0, 0, 0, 0, 0)) ctrtool_exit(1);
		if (ctrtool_syscall_errno(SYS_pivot_root, shared_mem_region, argv[2], argv[3], 0, 0, 0, 0)) ctrtool_exit(2);
		ctrtool_exit(0);
	} else {
		pid_t p_i = -1;
		int w_status = 0x300;
		while (p_i == -1) {
			p_i = waitpid(child_pid, &w_status, 0);
			if (p_i != -1) break;
			if (errno != EINTR) {
				break;
			}
		}
		int errno_f = *shared_mem_region;
		munmap(shared_mem_region, 4096);
		if (WIFEXITED(w_status)) {
			switch (WEXITSTATUS(w_status)) {
				case 0:
					return 0;
					break;
				case 1:
					fprintf(stderr, "chroot to %s failed: %s\n", argv[1], strerror(errno_f));
					return 2;
					break;
				case 2:
					fprintf(stderr, "pivot_root(\"%s\", \"%s\") failed: %s\n", argv[2], argv[3], strerror(errno_f));
					return 3;
					break;
			}
		}
		fprintf(stderr, "some other error occurred\n");
	}
	return 4;
}
