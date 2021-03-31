#include <sys/types.h>
struct ctrtool_tty_proxy {
	int width;
	int height;
	int master_fd;
	int slave_fd;
	int stdin_pipe_fd[2];
	int stdout_pipe_fd[2];
	int stderr_pipe_fd[2];
	const char *ptmx_file;
	int ultimate_stdin_dest;
	int ultimate_stdout_src;
	int ultimate_stderr_src;
	unsigned use_stderr_pipe:1;
	unsigned use_stdio_pipe:1;
	unsigned host_is_tty:1;
};
int ctrtool_open_tty_proxy(struct ctrtool_tty_proxy *options);
int ctrtool_tty_proxy_child(struct ctrtool_tty_proxy *options);
void ctrtool_tty_proxy_master(struct ctrtool_tty_proxy *options);
int ctrtool_tty_proxy_mainloop(struct ctrtool_tty_proxy *options, pid_t child_pid, int *child_wait_status);
