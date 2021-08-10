#include "ctrtool_ppid_check.h"
#include <errno.h>
#include <sys/prctl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
const char *ctrtool_ppid_check_run(struct ctrtool_ppid_check_args *args) {
	uint64_t current_sigmask = 0;
	if (ctrtool_syscall_errno(__NR_rt_sigprocmask, &errno, SIG_SETMASK, 0, &current_sigmask, sizeof(current_sigmask), 0, 0)) {
		return "sigprocmask";
	}
	current_sigmask &= ~args->unblocked_signals;
	current_sigmask |= args->blocked_signals;
	if (ctrtool_syscall_errno(__NR_rt_sigprocmask, &errno, SIG_SETMASK, &current_sigmask, 0, sizeof(current_sigmask), 0, 0)) {
		return "sigprocmask";
	}
	for (int i = 0; i < 64; i++) {
		if (args->ignored_signals & (1ULL << i)) {
			struct sigaction action = {};
			action.sa_handler = SIG_IGN;
			if (ctrtool_syscall_errno(__NR_rt_sigaction, &errno, i+1, &action, 0, sizeof(uint64_t), 0, 0) == SIG_ERR) {
				return "set SIG_IGN";
			}
		}
		if (args->default_signals & (1ULL << i)) {
			struct sigaction action = {};
			action.sa_handler = SIG_DFL;
			if (ctrtool_syscall_errno(__NR_rt_sigaction, &errno, i+1, &action, 0, sizeof(uint64_t), 0, 0) == SIG_ERR) {
				return "set SIG_DFL";
			}
		}
	}
	if (args->set_subreaper) {
		if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
			return "PR_SET_CHILD_SUBREAPER";
		}
	}
	if (args->set_pdeathsig) {
		if (prctl(PR_SET_PDEATHSIG, args->pdeathsig, 0, 0, 0)) {
			return "PR_SET_PDEATHSIG";
		}
	}
	pid_t actual_pid = getpid();
	pid_t actual_ppid = getppid();
	if (args->check_ppid) {
		if (args->expected_ppid != actual_ppid) {
			fprintf(stderr, "ppid = %lu, expected_ppid = %lu\n", (unsigned long) actual_ppid, args->expected_ppid);
			errno = ESRCH;
			return "Unexpected PPID";
		}
	}
	if (args->set_nnp) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			return "PR_SET_NO_NEW_PRIVS";
		}
	}
	if (args->set_alarm) {
		alarm(args->alarm_time);
	}
	if (args->set_setsid) {
		if (setsid() < 0) {
			return "setsid";
		}
	}
	if (args->setenv_prefix) {
		if (ctrtool_setenv_num_prefix(args->setenv_prefix, 0, "_PID", actual_pid)) {
			return "ctrtool_setenv_num_prefix";
		}
		if (ctrtool_setenv_num_prefix(args->setenv_prefix, 0, "_PPID", actual_ppid)) {
			return "ctrtool_setenv_num_prefix";
		}
	}
	return NULL;
}
