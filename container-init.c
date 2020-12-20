#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <linux/capability.h>
#include <errno.h>
int main(int argc, char **argv, char **envp) {
	if ((syscall(SYS_setreuid, (uint32_t) -2, (uint32_t) -2) == -1) && errno == EINVAL) {
		if (syscall(SYS_prctl, PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0)) goto fail;
		pid_t r = syscall(SYS_clone, CLONE_NEWPID|SIGCHLD, 0, 0, 0, 0);
		if (r == 0) {
			if (syscall(SYS_setsid, 0)) goto fail;
			if (syscall(SYS_dup2, 2, 1) != 1) goto fail;
			if (syscall(SYS_pivot_root, ".", ".")) goto fail;
			if (syscall(SYS_mount, "none", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, 0)) goto fail;
			if (syscall(SYS_umount2, ".", MNT_DETACH)) goto fail;
			errno = 0;
			syscall(SYS_execve, argv[1], &argv[1], envp);
		} else if (r > 0) {
			uint32_t pid_n = r;
			char buf[16] = {0};
			int c = 14;
			while (pid_n && c >= 0) {
				buf[c] = (pid_n % 10) + '0';
				pid_n /= 10;
				c--;
			}
			int i = 0;
			for (; i < 15; i++) {
				if (buf[i]) break;
			}
			buf[15] = '\n';
			if (i < 15) {
				syscall(SYS_write, 1, &buf[i], 16 - i);
			}
			return 0;
		} else goto fail;
	}
fail:
	return errno;
}
