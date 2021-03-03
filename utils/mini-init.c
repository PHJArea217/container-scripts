#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <wait.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <stdint.h>
#include <getopt.h>
#include <time.h>
#include <syscall.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <signal.h>
#include <linux/wait.h>
#include "ctrtool-common.h"
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#define M_SIGRTMAX 64
struct process_state {
	struct process_state *next;
	char **argv;
	int *inherit_fds;
	size_t nr_inherit_fds;
	unsigned int nr_args;
	char *ctty_in;
	char *ctty_out;
	char *ctty_err;
	time_t respawn_delay;
	pid_t current_pid;
	int pidfd;
	unsigned running:1;
	unsigned has_wait:1;
	unsigned do_respawn:1;
	unsigned set_listen_pid:1;
	struct timespec respawn_at;
};
static void reset_blocked_signals(void) {
	sigset_t s = {{0}};
	if (sigprocmask(SIG_SETMASK, &s, NULL)) _exit(1);
}
static void set_safe_fd(const char *pathname, int mode, int desired_fd) {
	if (!pathname) return;
	int f = open(pathname, mode);
	if (f == -1) _exit(1);
	if (f < 3) {
		int new_f = fcntl(f, F_DUPFD, 3);
		if (new_f == -1) _exit(1);
		close(f);
		f = new_f;
	}
	if (dup2(f, desired_fd) < 0) _exit(1);
	close(f);
}
static int fd_share_mode = 0;
static void run_process(struct process_state *state, const struct timespec *current_time, int first) {
	if (state->has_wait) {
		state->has_wait = 0;
		goto process_terminate_restart;
	}
	if (state->pidfd >= 0) {
		siginfo_t info = {0};
		int waitid_result = waitid(P_PIDFD, state->pidfd, &info, WNOHANG);
		if (waitid_result) return;
		if (info.si_pid) {
			goto process_terminate_restart;
		}
	} else if (state->running) {
		pid_t wait_result = waitpid(state->current_pid, NULL, WNOHANG);
		if (state->current_pid == wait_result) goto process_terminate_restart;
	} else if (state->do_respawn || first) {
		/* The process is not running */
		if ((current_time->tv_sec > state->respawn_at.tv_sec)
				|| ((current_time->tv_sec == state->respawn_at.tv_sec) && (current_time->tv_nsec >= state->respawn_at.tv_nsec))) {
			pid_t child_pid = fork();
			if (child_pid == -1) {
				goto process_terminate_restart;
			} else if (child_pid == 0) {
				reset_blocked_signals();
				if (setsid() < 0) _exit(1);
				set_safe_fd(state->ctty_in, O_RDONLY, 0);
				set_safe_fd(state->ctty_out, O_WRONLY, 1);
				set_safe_fd(state->ctty_err, O_WRONLY, 2);
				if (state->set_listen_pid) {
					ctrtool_mini_init_set_listen_pid_fds(state->nr_inherit_fds);
				}
				if (fd_share_mode) {
					ctrtool_mini_init_set_fds(state->inherit_fds, state->nr_inherit_fds);
				}
				execv(state->argv[0], state->argv);
				_exit(127);
			}
			state->current_pid = child_pid;
#if 0
			int pid_fd = syscall(SYS_pidfd_open, child_pid, 0);
			state->pidfd = pid_fd;
#else
			state->pidfd = -1;
#endif
			state->running = 1;
		}
	}
	return;
	/* Process has successfully terminated */
process_terminate_restart:
	state->current_pid = 0;
	if (state->pidfd >= 0) close(state->pidfd);
	state->pidfd = -1;
	state->running = 0;
	if (state->do_respawn) {
		state->respawn_at.tv_sec = current_time->tv_sec + state->respawn_delay;
		state->respawn_at.tv_nsec = current_time->tv_nsec;
	}
}
#define INIT_SIGNAL_EVENT_NONE 0
#define INIT_SIGNAL_EVENT_REBOOT 1
#define INIT_SIGNAL_EVENT_POWEROFF 2
#define INIT_SIGNAL_EVENT_HALT 3
#define INIT_SIGNAL_EVENT_CONTAINER_EXIT 4
#define INIT_SIGNAL_EVENT_RELOAD 5
#define INIT_SIGNAL_EVENT_GENERIC 6
#define INIT_SIGNAL_EVENT_TERM_RELOAD 7
struct init_signal_event {
	int event_type;
	char *script_pre;
	char *script_post;
};
static fd_set global_mask = {0};
static struct init_signal_event signal_table[M_SIGRTMAX+1];
static char *x_strdup(const char *str) {
	char *r = strdup(str);
	if (!r) {
		exit(1);
	}
	return r;
}
static int compare_time(const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec > b->tv_sec) return 1;
	if (a->tv_sec < b->tv_sec) return -1;
	if (a->tv_nsec > b->tv_nsec) return 1;
	if (a->tv_nsec < b->tv_nsec) return -1;
	return 0;
}
static void run_script(const char *name, int sig) {

	char buf[15] = {0};
	if (snprintf(buf, 15, "%d", sig) < 0) return;
	pid_t pid = fork();
	if (pid == 0) {
		reset_blocked_signals();
		execl(name, name, buf, NULL);
		_exit(127);
	}
}

static int ctr_scripts_mini_init_main_c(int argc, char **argv, int new_version) {
	struct process_state *all_procs = NULL;
	unsigned int current_signal = 0;
	int opt = 0;
	FD_ZERO(&global_mask);
	/* TODO: use - option for command arguments */
	static const char *my_optstring = "-n:s:c:a:0:1:2:C:r:i:I:f:pS";
	while ((opt = getopt(argc, argv, new_version ? my_optstring : &my_optstring[1])) >= 0) {
		switch(opt) {
			case 'n':
				;struct process_state *new_p = calloc(sizeof(struct process_state), 1);
				new_p->next = all_procs;
				new_p->pidfd = -1;
				new_p->argv = calloc(sizeof(char *), 2);
				new_p->nr_args = 2;
				new_p->argv[0] = x_strdup(optarg);
				all_procs = new_p;
				break;
			case 's':
				;unsigned int sig_num = strtoul(optarg, NULL, 0);
				if (sig_num > M_SIGRTMAX) {
					fprintf(stderr, "Invalid signal %u\n", sig_num);
					return 1;
				}
				/* FIXME: signal names */
				current_signal = sig_num;
				if (current_signal > 0) FD_SET(current_signal-1, &global_mask);
				break;
			case 1:
			case 'c':
				if (!all_procs) {
					fputs("Cannot use -c before -n\n", stderr);
					return 1;
				}
				unsigned int nr_args_curr = all_procs->nr_args++;
				all_procs->argv = reallocarray(all_procs->argv, sizeof(char *), all_procs->nr_args);
				if (!all_procs->argv) return 1;
				all_procs->argv[nr_args_curr-1] = x_strdup(optarg);
				all_procs->argv[nr_args_curr] = NULL;
				break;
			case 'a':
				if (!current_signal) {
					fputs("Cannot use -a before -s\n", stderr);
					return 1;
				}
				/* FIXME: labels */
				signal_table[current_signal].event_type = atoi(optarg);
				break;
			case '0':
				if (!all_procs) {
					fputs("Cannot use -0 before -n\n", stderr);
					return 1;
				}
				free(all_procs->ctty_in);
				all_procs->ctty_in = x_strdup(optarg);
				break;
			case '1':
				if (!all_procs) {
					fputs("Cannot use -1 before -n\n", stderr);
					return 1;
				}
				free(all_procs->ctty_out);
				all_procs->ctty_out = x_strdup(optarg);
				break;
			case '2':
				if (!all_procs) {
					fputs("Cannot use -2 before -n\n", stderr);
					return 1;
				}
				free(all_procs->ctty_err);
				all_procs->ctty_err = x_strdup(optarg);
				break;
			case 'C':
				if (!all_procs) {
					fputs("Cannot use -C before -n\n", stderr);
					return 1;
				}
				free(all_procs->ctty_in);
				all_procs->ctty_in = x_strdup(optarg);
				free(all_procs->ctty_out);
				all_procs->ctty_out = x_strdup(optarg);
				free(all_procs->ctty_err);
				all_procs->ctty_err = x_strdup(optarg);
				break;
			case 'r':
				if (!all_procs) {
					fputs("Cannot use -r before -n\n", stderr);
					return 1;
				}
				all_procs->respawn_delay = atoi(optarg);
				all_procs->do_respawn = 1;
				break;
			case 'i':
				if (!current_signal) {
					fputs("Cannot use -i before -s\n", stderr);
					return 1;
				}
				free(signal_table[current_signal].script_pre);
				signal_table[current_signal].script_pre = x_strdup(optarg);
				break;
			case 'I':
				if (!current_signal) {
					fputs("Cannot use -I before -s\n", stderr);
					return 1;
				}
				free(signal_table[current_signal].script_post);
				signal_table[current_signal].script_post = x_strdup(optarg);
				break;
			case 'f':
				if (!fd_share_mode) {
					fputs("-f can only be used in -S mode\n", stderr);
					return 1;
				}
				if (!all_procs) {
					fputs("Cannot use -f before -n\n", stderr);
					return 1;
				}
				all_procs->inherit_fds = reallocarray(all_procs->inherit_fds, sizeof(int), ++all_procs->nr_inherit_fds);
				if (!all_procs->inherit_fds) {
					return 1;
				}
				int i_fd = atoi(optarg);
				if (i_fd < 3) {
					fputs("Inherited file descriptor must be >= 3\n", stderr);
					return 1;
				}
				all_procs->inherit_fds[all_procs->nr_inherit_fds - 1] = i_fd;
				break;
			case 'S':
				fd_share_mode = 1;
				break;
			case 'p':
				if (!all_procs) {
					fputs("Cannot use -p before -n\n", stderr);
					return 1;
				}
				all_procs->set_listen_pid = 1;
				break;
			default:
				/* FIXME: help text */
				return 1;
				break;
		}
	}
	if (getpid() != 1) {
		fputs("Must run as PID 1\n", stderr);
		return 1;
	}
	if (fd_share_mode) {
		int test_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (test_fd < 0) {
			goto self_test_failed;
		}
		if (fcntl(test_fd, F_GETFD, 0) < 0) goto self_test_failed;
		if (ctrtool_close_range(test_fd, test_fd, 0)) goto self_test_failed;
		if (fcntl(test_fd, F_GETFD, 0) >= 0) goto self_test_failed;
		goto self_test_done;
self_test_failed:
		fputs("close_range self test failed. -S option is currently only supported on\nLinux kernels 5.9 and up\n", stderr);
		return 1;
	}
self_test_done:
	FD_SET(SIGCHLD-1, &global_mask);
	if (syscall(SYS_rt_sigprocmask, SIG_BLOCK, &global_mask, NULL, 8)) {
		return 1;
	}
	struct timespec current_time = {0, 0};
	clock_gettime(CLOCK_MONOTONIC, &current_time);
	for (struct process_state *state = all_procs; state; state = state->next) {
		run_process(state, &current_time, 1);
	}
	char *script_pre = NULL;
	char *script_post = NULL;
	int event_type = 0;
	int reboot_cmd = 0;
	int term_sig = 0;
	while (!event_type) {
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		struct timespec latest_expiration = {current_time.tv_sec + 30, current_time.tv_nsec};
		for (struct process_state *state = all_procs; state; state = state->next) {
			if (state->do_respawn && !state->running) {
				if (compare_time(&state->respawn_at, &latest_expiration) < 0) {
					latest_expiration = state->respawn_at;
				}
			}
		}
		struct timespec time_to_wait = {0, 0};
		if (compare_time(&current_time, &latest_expiration) < 0) {
			time_to_wait.tv_sec = latest_expiration.tv_sec - current_time.tv_sec;
			if (latest_expiration.tv_nsec < current_time.tv_nsec) {
				time_to_wait.tv_nsec = 1000000000 + latest_expiration.tv_nsec - current_time.tv_nsec;
				time_to_wait.tv_sec--;
			} else {
				time_to_wait.tv_nsec = latest_expiration.tv_nsec - current_time.tv_nsec;
			}
		}
		siginfo_t my_siginfo = {0};
		int sig = syscall(SYS_rt_sigtimedwait, &global_mask, &my_siginfo, &time_to_wait, 8);
		if ((sig > 0) && (sig <= M_SIGRTMAX)) {
			switch(signal_table[sig].event_type) {
				case INIT_SIGNAL_EVENT_GENERIC:
					run_script(signal_table[sig].script_pre, sig);
					break;
				case INIT_SIGNAL_EVENT_POWEROFF:
					event_type = INIT_SIGNAL_EVENT_REBOOT;
					reboot_cmd = LINUX_REBOOT_CMD_POWER_OFF;
					script_pre = signal_table[sig].script_pre;
					script_post = signal_table[sig].script_post;
					break;
				case INIT_SIGNAL_EVENT_HALT:
					event_type = INIT_SIGNAL_EVENT_REBOOT;
					reboot_cmd = LINUX_REBOOT_CMD_HALT;
					script_pre = signal_table[sig].script_pre;
					script_post = signal_table[sig].script_post;
					break;
				case INIT_SIGNAL_EVENT_CONTAINER_EXIT:
					event_type = INIT_SIGNAL_EVENT_CONTAINER_EXIT;
					reboot_cmd = 0;
					script_pre = signal_table[sig].script_pre;
					script_post = signal_table[sig].script_post;
					break;
				case INIT_SIGNAL_EVENT_REBOOT:
					event_type = INIT_SIGNAL_EVENT_REBOOT;
					reboot_cmd = LINUX_REBOOT_CMD_RESTART;
					script_pre = signal_table[sig].script_pre;
					script_post = signal_table[sig].script_post;
					break;
				case INIT_SIGNAL_EVENT_RELOAD:
					;char buf[15] = {0};
					if (snprintf(buf, 15, "%d", sig) < 0) break;
					if (signal_table[sig].script_pre) execl(signal_table[sig].script_pre, signal_table[sig].script_pre, buf, NULL);
					break;
				case INIT_SIGNAL_EVENT_TERM_RELOAD:
					event_type = INIT_SIGNAL_EVENT_TERM_RELOAD;
					reboot_cmd = 0;
					script_pre = signal_table[sig].script_pre;
					script_post = signal_table[sig].script_post;
					break;
			}
			term_sig = sig;
		}
		if (event_type) break;
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		if ((sig == SIGCHLD) && (my_siginfo.si_pid)) {
			for (struct process_state *state = all_procs; state; state = state->next) {
				if (state->current_pid == my_siginfo.si_pid) {
					run_process(state, &current_time, 0);
				}
			}
		}
		pid_t my_pid = 0;
		while ((my_pid = waitpid(-1, NULL, WNOHANG)) > 0) {
			for (struct process_state *state = all_procs; state; state = state->next) {
				if (state->current_pid == my_pid) {
					state->has_wait = 1;
					run_process(state, &current_time, 0);
				}
			}
		}
		for (struct process_state *state = all_procs; state; state = state->next) {
			if (!state->running) run_process(state, &current_time, 0);
		}
	}
	if (script_pre) run_script(script_pre, term_sig);
	fputs("Beginning system shutdown\n", stderr);
	nanosleep(&(struct timespec) {2, 0}, NULL);
	fputs("Send SIGTERM to all processes\n", stderr);
	kill(-1, SIGTERM);
	nanosleep(&(struct timespec) {2, 0}, NULL);
	fputs("Send SIGKILL to all processes\n", stderr);
	kill(-1, SIGKILL);
	nanosleep(&(struct timespec) {2, 0}, NULL);
	fputs("Restarting system...\n", stderr);
	switch(event_type) {
		case INIT_SIGNAL_EVENT_TERM_RELOAD:
			;char buf[15] = {0};
			if (snprintf(buf, 15, "%d", term_sig) < 0) break;
			if (script_post) execl(script_post, script_post, buf, NULL);
			sync();
		case INIT_SIGNAL_EVENT_REBOOT:
			if (script_post) run_script(script_post, term_sig);
			sync();
			reboot(reboot_cmd);
			break;
		case INIT_SIGNAL_EVENT_CONTAINER_EXIT:
			if (script_post) run_script(script_post, term_sig);
			break;
	}
	return 0;
}
int ctr_scripts_mini_init2_main(int argc, char **argv) {
	return ctr_scripts_mini_init_main_c(argc, argv, 1);
}
int ctr_scripts_mini_init_main(int argc, char **argv) {
	return ctr_scripts_mini_init_main_c(argc, argv, 0);
}
