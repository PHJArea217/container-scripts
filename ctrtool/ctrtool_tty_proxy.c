#define _GNU_SOURCE
#include "ctrtool-common.h"
#include "ctrtool_relay.h"
#include "ctrtool_tty_proxy.h"
#include <termios.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <wait.h>
#include <string.h>
int ctrtool_open_tty_proxy(struct ctrtool_tty_proxy *options) {
	if (options->width < 0) options->width = 0;
	if (options->height < 0) options->height = 0;
	struct winsize term_size = {0};
	int ioctl_result = ctrtool_syscall(SYS_ioctl, STDIN_FILENO, TIOCGWINSZ, &term_size, 0, 0, 0);
	if (ioctl_result < 0) {
		options->host_is_tty = 0;
	} else {
		options->host_is_tty = 1;
		if (options->width == 0) options->width = term_size.ws_col;
		if (options->height == 0) options->height = term_size.ws_row;
	}
	if (options->use_stderr_pipe) {
		if (pipe(options->stderr_pipe_fd)) {
			return -1;
		}
	} else {
		options->stderr_pipe_fd[0] = -1;
		options->stderr_pipe_fd[1] = -1;
	}
	if (options->use_stdio_pipe) {
		if (pipe(options->stdout_pipe_fd)) {
			goto close_stderr_pipe;
		}
		if (pipe(options->stdin_pipe_fd)) {
			goto close_stdout_pipe;
		}
		options->master_fd = -1;
		options->slave_fd = -1;
	} else {
		int master_fd;
		if (options->ptmx_file) {
			master_fd = open(options->ptmx_file, O_RDWR | O_NOCTTY);
		} else {
			master_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
		}
		if (master_fd < 0) {
			goto close_stderr_pipe;
		}
		if (unlockpt(master_fd)) goto close_stderr_pipe;
		struct winsize ws_new = {0};
		ws_new.ws_col = options->width;
		ws_new.ws_row = options->height;
		/* Ignore errors */
		ctrtool_syscall(SYS_ioctl, master_fd, TIOCSWINSZ, &ws_new, 0, 0, 0);
		options->master_fd = master_fd;
		options->stdin_pipe_fd[0] = -1;
		options->stdin_pipe_fd[1] = -1;
		options->stdout_pipe_fd[0] = -1;
		options->stdout_pipe_fd[1] = -1;
		options->slave_fd = -1;
	}
	options->is_init = 1;
	return 0;
close_stdout_pipe:
	CTRTOOL_CLOSE_NO_ERROR(options->stdout_pipe_fd[0]);
	CTRTOOL_CLOSE_NO_ERROR(options->stdout_pipe_fd[1]);
close_stderr_pipe:
	CTRTOOL_CLOSE_NO_ERROR(options->stderr_pipe_fd[0]);
	CTRTOOL_CLOSE_NO_ERROR(options->stderr_pipe_fd[1]);
	return -1;
}
/* TODO: cleanup */
#define CHOWN_IF_VALID_FD(fd, uid, gid) do {if (fd >= 0) {if (fd < 3) {errno = EINVAL; return -1;} else {if (fchown(fd, uid, gid)) return -1;}}} while (0)
int ctrtool_tty_proxy_chown_slave(struct ctrtool_tty_proxy *options, uid_t uid, gid_t gid) {
	assert(options->is_init);
	CHOWN_IF_VALID_FD(options->stdin_pipe_fd[0], uid, gid);
	CHOWN_IF_VALID_FD(options->stdout_pipe_fd[1], uid, gid);
	CHOWN_IF_VALID_FD(options->stderr_pipe_fd[1], uid, gid);
	if (options->master_fd >= 3) {
		if (options->ptmx_file) {
			int new_slave_fd = ioctl(options->master_fd, TIOCGPTPEER, O_RDWR|O_CLOEXEC|O_NOCTTY);
			if (new_slave_fd < 0) {
				return -1;
			}
			if (fchown(new_slave_fd, uid, gid)) {
				CTRTOOL_CLOSE_NO_ERROR(new_slave_fd);
				return -1;
			}
			CTRTOOL_CLOSE_NO_ERROR(new_slave_fd);
		} else {
			char pts_name_buf[48] = {0};
			if (ptsname_r(options->master_fd, pts_name_buf, 48)) {
				return -1;
			}
			if (chown(pts_name_buf, uid, gid)) {
				return -1;
			}
		}
	}
	return 0;
}
int ctrtool_tty_proxy_child(struct ctrtool_tty_proxy *options) {
	assert(options->is_init);
	if (options->use_stdio_pipe) {
		CTRTOOL_CLOSE_NO_ERROR(options->stdout_pipe_fd[0]);
		CTRTOOL_CLOSE_NO_ERROR(options->stdin_pipe_fd[1]);
		if (dup2(options->stdin_pipe_fd[0], 0) < 0) return -1;
		if (dup2(options->stdout_pipe_fd[1], 1) < 0) return -1;
		CTRTOOL_CLOSE_NO_ERROR(options->stdin_pipe_fd[0]);
	} else {
		int new_slave_fd_stdin = -1;
		int new_slave_fd_stdout = -1;
		if (options->ptmx_file) { /* Have a /dev/ptmx file -> use the ioctl */
			new_slave_fd_stdin = ioctl(options->master_fd, TIOCGPTPEER, O_RDWR);
			if (new_slave_fd_stdin < 0) {
				return -1;
			}
			if (dup2(new_slave_fd_stdin, 0) < 0) return -1;
			CTRTOOL_CLOSE_NO_ERROR(new_slave_fd_stdin);

			new_slave_fd_stdout = ioctl(options->master_fd, TIOCGPTPEER, O_RDWR);
			if (new_slave_fd_stdout < 0) {
				return -1;
			}
			if (dup2(new_slave_fd_stdout, 1) < 0) return -1;
		} else {
			char pts_name_buf[48] = {0};
			if (ptsname_r(options->master_fd, pts_name_buf, 48)) {
				return -1;
			}
			if ((new_slave_fd_stdin = open(pts_name_buf, O_RDWR)) < 0) {
				return -1;
			}
			if (dup2(new_slave_fd_stdin, 0) < 0) return -1;
			CTRTOOL_CLOSE_NO_ERROR(new_slave_fd_stdin);

			new_slave_fd_stdout = open(pts_name_buf, O_RDWR);
			if (new_slave_fd_stdout < 0) {
				return -1;
			}
			if (dup2(new_slave_fd_stdout, 1) < 0) return -1;
		}
		options->slave_fd = new_slave_fd_stdout;
		CTRTOOL_CLOSE_NO_ERROR(options->master_fd);
	}
	if (options->use_stderr_pipe) {
		CTRTOOL_CLOSE_NO_ERROR(options->stderr_pipe_fd[0]);
		if (dup2(options->stderr_pipe_fd[1], 2) < 0) return -1;
	} else {
		if (options->use_stdio_pipe) {
			if (dup2(options->stdout_pipe_fd[1], 2) < 0) return -1;
		} else {
			if (dup2(options->slave_fd, 2) < 0) return -1;
		}
	}
	CTRTOOL_CLOSE_NO_ERROR(options->slave_fd);
	CTRTOOL_CLOSE_NO_ERROR(options->stderr_pipe_fd[1]);
	CTRTOOL_CLOSE_NO_ERROR(options->stdout_pipe_fd[1]);
	return 0;
}
void ctrtool_tty_proxy_master(struct ctrtool_tty_proxy *options, int make_cloexec) {
	assert(options->is_init);
	if (options->use_stdio_pipe) {
		CTRTOOL_CLOSE_NO_ERROR(options->stdout_pipe_fd[1]);
		CTRTOOL_CLOSE_NO_ERROR(options->stdin_pipe_fd[0]);
		options->ultimate_stdin_dest = options->stdin_pipe_fd[1];
		options->ultimate_stdout_src = options->stdout_pipe_fd[0];
		options->ultimate_stderr_src = -1;
		if (make_cloexec) {
			assert(ctrtool_make_fd_cloexec(options->stdin_pipe_fd[1], 1) == 0);
			assert(ctrtool_make_fd_cloexec(options->stdout_pipe_fd[0], 1) == 0);
		}
	} else {
		CTRTOOL_CLOSE_NO_ERROR(options->slave_fd);
		options->ultimate_stdin_dest = options->master_fd;
		options->ultimate_stdout_src = options->master_fd;
		options->ultimate_stderr_src = -1;
		if (make_cloexec) {
			assert(ctrtool_make_fd_cloexec(options->master_fd, 1) == 0);
		}
	}
	if (options->use_stderr_pipe) {
		CTRTOOL_CLOSE_NO_ERROR(options->stderr_pipe_fd[1]);
		options->ultimate_stderr_src = options->stderr_pipe_fd[0];
		if (make_cloexec) {
			assert(ctrtool_make_fd_cloexec(options->stderr_pipe_fd[0], 1) == 0);
		}
	}
}
static volatile sig_atomic_t sigchld_received = 0;
static void sigchld_handler(int signo) {
	if (signo == SIGCHLD) sigchld_received = 1;
}
static int block_sigchld(sigset_t *poll_sigset) {
	uint64_t linux_sigset_sigchld_only = 1<<(SIGCHLD-1);
	if (ctrtool_syscall_errno(SYS_rt_sigprocmask, &errno, SIG_BLOCK, &linux_sigset_sigchld_only, poll_sigset, sizeof(uint64_t), 0, 0)) {
		return -1;
	}
	if (signal(SIGCHLD, sigchld_handler) == SIG_ERR) {
		return -1;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		return -1;
	}
	sigdelset(poll_sigset, SIGCHLD);
	return 0;
}
int ctrtool_tty_proxy_mainloop(struct ctrtool_tty_proxy *options, pid_t child_pid, int *child_wait_status) {
	assert(options->is_init);
	struct termios orig_ios = {0};
	int restore_term = 0;
	int restore_sigmask = 0;
	int ret = -1;
	if ((options->master_fd >= 0) && (tcgetattr(0, &orig_ios) == 0)) {
		restore_term = 1;
		struct termios new_ios = {0};
		memcpy(&new_ios, &orig_ios, sizeof(struct termios));
		new_ios.c_lflag &= ~(ISIG|ICANON|ECHO);
		if (tcsetattr(0, TCSANOW, &new_ios)) {
			return -1;
		}
	}
	sigset_t poll_sigmask = {0};
	if (block_sigchld(&poll_sigmask)) {
		goto last;
	}
	restore_sigmask = 1;
	int fd_wait = 0;
	int child_wait = 0;
	pid_t out_pid = waitpid(child_pid, child_wait_status, WNOHANG);
	if (out_pid < 0) {
		goto last;
	}
	if (out_pid > 0) {
		child_wait = 1;
		fd_wait = 2;
#if 0		
		ret = 0;
		goto last;
#endif
	}
	struct ctrtool_relay *stdin_relay = ctrtool_relay_new(STDIN_FILENO, options->ultimate_stdin_dest, 4096, 0);
	if (!stdin_relay) goto last;
	struct ctrtool_relay *stdout_relay = ctrtool_relay_new(options->ultimate_stdout_src, STDOUT_FILENO, 4096, 0);
	if (!stdout_relay) goto close_stdin;
	struct ctrtool_relay *stderr_relay = NULL;
	if (options->ultimate_stderr_src >= 0) {
		stderr_relay = ctrtool_relay_new(options->ultimate_stderr_src, STDERR_FILENO, 4096, 0);
		if (!stderr_relay) goto close_stdout;
	}
	while (1) {
		struct pollfd pfds[6] = {0};
		if (fd_wait != 3) {
			if (ctrtool_relay_can_poll_in(stdin_relay)) {
				pfds[0].fd = STDIN_FILENO;
				pfds[0].events = POLLIN;
			} else {
				pfds[0].fd = -1;
			}
			if (ctrtool_relay_can_poll_out(stdout_relay)) {
				pfds[1].fd = STDOUT_FILENO;
				pfds[1].events = POLLOUT;
			} else {
				pfds[1].fd = -1;
			}
			if (ctrtool_relay_can_poll_out(stdin_relay)) {
				pfds[2].fd = options->ultimate_stdin_dest;
				pfds[2].events = POLLOUT;
			} else {
				pfds[2].fd = -1;
			}
			if (ctrtool_relay_can_poll_in(stdout_relay)) {
				pfds[3].fd = options->ultimate_stdout_src;
				pfds[3].events = POLLIN;
			} else {
				pfds[3].fd = -1;
			}
			if (stderr_relay) {
				if (ctrtool_relay_can_poll_in(stderr_relay)) {
					pfds[4].fd = options->ultimate_stderr_src;
					pfds[4].events = POLLIN;
				} else {
					pfds[4].fd = -1;
				}
				if (ctrtool_relay_can_poll_out(stderr_relay)) {
					pfds[5].fd = STDERR_FILENO;
					pfds[5].events = POLLOUT;
				} else {
					pfds[5].fd = -1;
				}
			}
		} else {
			pfds[0].fd = -1;
			pfds[1].fd = -1;
			pfds[2].fd = -1;
			pfds[3].fd = -1;
			pfds[4].fd = -1;
			pfds[5].fd = -1;
			if (child_wait) {
				break;
			}
			if (ctrtool_syscall_errno(SYS_rt_sigsuspend, &errno, &poll_sigmask, sizeof(uint64_t), 0, 0, 0, 0)) {
				if (errno == EINTR) {
					goto after_poll;
				}
			}
			goto close_stderr;
		}
		int poll_result = ctrtool_syscall_errno(SYS_ppoll, &errno, pfds, stderr_relay ? 6 : 4, NULL, &poll_sigmask, sizeof(uint64_t), 0);
		if ((poll_result < 0) && (errno != EINTR)) {
			goto close_stderr;
		}
after_poll:
		if ((!child_wait) && sigchld_received) {
			pid_t w_pid = waitpid(child_pid, child_wait_status, WNOHANG);
			if ((w_pid < 0) && (errno == ECHILD)) {
				*child_wait_status = 0x100; /* exit(1) */
				child_wait = 1;
			//	goto child_terminated;
			} else if (w_pid == child_pid) {
			//	goto child_terminated;
				child_wait = 1;
			}
		}
		if (child_wait && (fd_wait & 1)) {
			break;
		}
		if (pfds[0].revents) {
			ctrtool_relay_consume(stdin_relay);
			ctrtool_relay_release(stdin_relay);
		}
		if (pfds[1].revents) {
			ctrtool_relay_release(stdout_relay);
		}
		if (pfds[2].revents) {
			ctrtool_relay_release(stdin_relay);
		}
		if (pfds[3].revents) {
			ctrtool_relay_consume(stdout_relay);
			ctrtool_relay_release(stdout_relay);
		}
		if (pfds[4].revents) {
			ctrtool_relay_consume(stderr_relay);
			ctrtool_relay_release(stderr_relay);
		}
		if (pfds[5].revents) {
			ctrtool_relay_release(stderr_relay);
		}
		if ((child_wait) || (stdin_relay->state == CTRTOOL_RELAY_STATE_TERMINATED)) {
			fd_wait |= 2;
			stdin_relay->state = CTRTOOL_RELAY_STATE_TERMINATED;
			stdin_relay->buffer_ptr = 0;
		}
		if ((stdout_relay->state == CTRTOOL_RELAY_STATE_TERMINATED) && ((!stderr_relay) || (stderr_relay->state == CTRTOOL_RELAY_STATE_TERMINATED))) {
			fd_wait |= 1;
		}
		continue;
#if 0
child_terminated:
		stdin_relay->state = CTRTOOL_RELAY_STATE_TERMINATED;
		stdout_relay->state = CTRTOOL_RELAY_STATE_INPUT_EOF;
		if (stderr_relay) stderr_relay->state = CTRTOOL_RELAY_STATE_INPUT_EOF;
#endif
	}
	ret = 0;
close_stderr:
	if (stderr_relay) ctrtool_relay_destroy(stderr_relay);
close_stdout:
	ctrtool_relay_destroy(stdout_relay);
close_stdin:
	ctrtool_relay_destroy(stdin_relay);
last:
	if (restore_term) {
		tcsetattr(0, TCSANOW, &orig_ios);
	}
	if (restore_sigmask) {
		ctrtool_syscall(SYS_rt_sigprocmask, SIG_SETMASK, &poll_sigmask, 0, sizeof(uint64_t), 0, 0);
	}
	return ret;
}
