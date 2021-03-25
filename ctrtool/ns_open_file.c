#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <syscall.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <wait.h>
#include <sys/mman.h>
#include <sched.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/nsfs.h>
#define CTRTOOL_NS_OPEN_FILE_MOUNT 'm'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_SOCKET 'n'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_TUNTAP 'T'
struct ns_open_file_req {
	int type;
	unsigned enter_userns:1;
	unsigned set_reuseaddr_or_tap:1;
	unsigned set_reuseport_or_no_pi:1;
	unsigned set_freebind:1;
	unsigned set_transparent:1;
	const char *ns_path;
	int sock_domain;
	int sock_type;
	int sock_protocol;
	int listen_backlog;
	struct sockaddr *bind_address;
	socklen_t bind_address_len;
	char *scope_id_name;
};
static int process_req(struct ns_open_file_req *req_text, int *result_fd, const char *tun_name) {
	int _f = -1;
	switch (req_text->type) {
		case CTRTOOL_NS_OPEN_FILE_MOUNT:
			_f = ctrtool_syscall(SYS_openat, AT_FDCWD, "/", O_RDONLY|O_PATH|O_DIRECTORY, 0, 0, 0);
			if (_f < 0) {
				result_fd[0] = -1;
				result_fd[1] = -_f;
				return 1;
			} else {
				result_fd[0] = _f;
				result_fd[1] = 0;
				return 0;
			}
			break;
		case CTRTOOL_NS_OPEN_FILE_NETWORK_SOCKET:
			_f = socket(req_text->sock_domain, req_text->sock_type, req_text->sock_protocol);
			if (_f < 0) {
				result_fd[0] = -1;
				result_fd[1] = errno;
				return 2;
			}
			int one = 1;
			if (req_text->set_reuseaddr_or_tap) {
				if (setsockopt(_f, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) goto close_f_fail;
			}
			if (req_text->set_reuseport_or_no_pi) {
				if (setsockopt(_f, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one))) goto close_f_fail;
			}
			if (req_text->set_freebind) {
				if (setsockopt(_f, SOL_IP, IP_FREEBIND, &one, sizeof(one))) goto close_f_fail;
			}
			if (req_text->set_transparent) {
				if (setsockopt(_f, SOL_IP, IP_TRANSPARENT, &one, sizeof(one))) goto close_f_fail;
			}
			if (req_text->bind_address) {
				if (req_text->bind_address_len == sizeof(struct sockaddr_in6)) {
					if (req_text->scope_id_name) {
						unsigned int scope_index = if_nametoindex(req_text->scope_id_name);
						if (!scope_index) goto close_f_fail;
						((struct sockaddr_in6 *) req_text->bind_address)->sin6_scope_id = scope_index;
					}
				}
				if (bind(_f, req_text->bind_address, req_text->bind_address_len)) {
					goto close_f_fail;
				}
			}
			if (req_text->listen_backlog) {
				if (listen(_f, req_text->listen_backlog)) {
					goto close_f_fail;
				}
			}
			result_fd[0] = _f;
			result_fd[1] = 0;
			return 0;
			break;
		case CTRTOOL_NS_OPEN_FILE_NETWORK_TUNTAP:
			_f = open(tun_name, O_RDWR, 0);
			if (_f < 0) {
				result_fd[0] = -1;
				result_fd[1] = errno;
				return 1;
			} else {
				result_fd[0] = _f;
				result_fd[1] = 0;
				return 0;
			}
			break;
	}
close_f_fail:
	result_fd[0] = -1;
	result_fd[1] = errno;
	close(_f);
	return -1;
}
int ctr_scripts_ns_open_file_main(int argc, char **argv) {
	struct ctrtool_arraylist things_to_add = {0};
	things_to_add.elem_size = sizeof(struct ns_open_file_req);
	struct ns_open_file_req *current = NULL;
	const char *tun_name = "/dev/net/tun";
	int opt = 0;
	while ((opt = getopt(argc, argv, "+mnTUM:N:d:t:p:l:4:6:z:")) > 0) {
		char *d_optarg = NULL;
		switch (opt) {
			case 'm':
			case 'n':
			case 'T':
				if (ctrtool_arraylist_expand_s(&things_to_add, NULL, 10, (void **) &current)) {
					perror("ctrtool_arraylist_expand");
					return 1;
				}
				current->type = opt;
				current->sock_domain = AF_INET6;
				current->sock_type = SOCK_STREAM;
				current->sock_protocol = 0;
				break;
			case 'U':
				if (!current) goto no_opt;
				current->enter_userns = 1;
				break;
			case 'M':
				tun_name = optarg;
				break;
			case 'N':
				if (!current) goto no_opt;
				current->ns_path = optarg;
				break;
			case 'd':
				if (!current) goto no_opt;
				current->sock_domain = atoi(optarg);
				break;
			case 't':
				if (!current) goto no_opt;
				current->sock_type = atoi(optarg);
				break;
			case 'p':
				if (!current) goto no_opt;
				current->sock_protocol = atoi(optarg);
				break;
			case 'l':
				if (!current) goto no_opt;
				current->listen_backlog = atoi(optarg);
				break;
			case '4':
			case '6':
				if (!current) goto no_opt;
				if (current->bind_address) goto already_address;
				d_optarg = strdup(optarg);
				if (!d_optarg) goto no_mem;
				char *saveptr = NULL;
				char *addr_part = strtok_r(d_optarg, ",", &saveptr);
				if (!addr_part) goto no_addr_part;
				char *port_part = strtok_r(NULL, ",", &saveptr);
				if (!port_part) goto no_addr_part;
				char *flags_part = strtok_r(NULL, ",", &saveptr);
				char *scope_id_part = NULL;
				if (flags_part) {
					scope_id_part = strtok_r(NULL, ",", &saveptr);
				}
				uint16_t port_part_n = htons(atoi(port_part));
				int numeric_scope_id = 0;
				if (flags_part) {
					while (*flags_part) {
						char next_flag = *flags_part;
						flags_part++;
						switch (next_flag) {
							case 'a':
								current->set_reuseaddr_or_tap = 1;
								break;
							case 'p':
								current->set_reuseport_or_no_pi = 1;
								break;
							case 'f':
								current->set_freebind = 1;
								break;
							case 't':
								current->set_transparent = 1;
								break;
							case 'I':
								numeric_scope_id = 1;
								break;
							case ':':
								break;
							default:
								fprintf(stderr, "Unknown flag %c\n", next_flag);
								exit(1);
						}
					}
				}
				if (opt == '4') {
					struct sockaddr_in *result = calloc(sizeof(struct sockaddr_in), 1);
					result->sin_family = AF_INET;
					result->sin_port = port_part_n;
					if (inet_pton(AF_INET, addr_part, &result->sin_addr) != 1) {
						goto no_addr_part;
					}
					current->bind_address = result;
					current->bind_address_len = sizeof(struct sockaddr_in);
				} else {
					struct sockaddr_in6 *result = calloc(sizeof(struct sockaddr_in6), 1);
					result->sin6_family = AF_INET6;
					result->sin6_port = port_part_n;
					if (inet_pton(AF_INET6, addr_part, &result->sin6_addr) != 1) {
						goto no_addr_part;
					}
					if (numeric_scope_id) {
						if (!scope_id_part) goto no_addr_part;
						result->sin6_scope_id = strtoul(scope_id_part, NULL, 0);
					}
					current->bind_address = result;
					current->bind_address_len = sizeof(struct sockaddr_in6);
					if (scope_id_part) {
						current->scope_id_name = strdup(scope_id_part);
						if (!current->scope_id_name) goto no_mem;
					}
				}
				break;
				/* FIXME: implement -z (arbitrary hex string as socket address, with domain included) */
			default:
				return 1;
		}
		continue;
no_opt:
		fprintf(stderr, "-%c may not be used before -m, -n, or -T\n", opt);
no_mem:
		return 1;
already_address:
		fprintf(stderr, "-%c already has an address\n", opt);
		return 1;
no_addr_part:
		fprintf(stderr, "Invalid address specification %s, must be of the form addr,port[,flags[,scope_id]]\n", optarg);
		return 1;
	}
	if (!argv[optind]) {
		fprintf(stderr, "%s: No program specified\n", argv[0]);
		return 1;
	}
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		perror("signal()");
		return 2;
	}
	struct ns_open_file_req *list_base = things_to_add.start;
	for (size_t i = 0; i < things_to_add.nr; i++) {
		current = &list_base[i];
		int out_fd = -1;
		if (current->ns_path) {
			int *shared_mem_region = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
			if (shared_mem_region == MAP_FAILED) {
				perror("mmap");
				return 2;
			}
			shared_mem_region[0] = -1;
			int ns_fd = open(current->ns_path, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC);
			if (ns_fd < 0) {
				perror("open namespace");
				return 2;
			}
			long child_pid = ctrtool_clone_onearg(CLONE_FILES|SIGCHLD);
			if (child_pid < 0) {
				errno = -child_pid;
				perror("clone()");
				return 2;
			}
			if (child_pid == 0) {
				if (current->enter_userns) {
					if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
						perror("PR_SET_DUMPABLE");
						ctrtool_exit(255);
					}
					int userns_fd = ioctl(ns_fd, NS_GET_USERNS, 0);
					if (userns_fd < 0) {
						shared_mem_region[0] = -1;
						shared_mem_region[1] = errno;
						__sync_synchronize();
						shared_mem_region[2] = 1;
						ctrtool_exit(3);
					}
					if (setns(userns_fd, CLONE_NEWUSER)) {
						shared_mem_region[0] = -1;
						shared_mem_region[1] = errno;
						__sync_synchronize();
						shared_mem_region[2] = 1;
						close(userns_fd);
						ctrtool_exit(4);
					}
					close(userns_fd);
				}
				long syscall_result = ctrtool_syscall(SYS_setns, ns_fd, ((current->type == CTRTOOL_NS_OPEN_FILE_MOUNT) ? CLONE_NEWNS : CLONE_NEWNET), 0, 0, 0, 0);
				if (syscall_result < 0) {
					shared_mem_region[0] = -1;
					shared_mem_region[1] = -syscall_result;
					__sync_synchronize();
					shared_mem_region[2] = 1;
					ctrtool_exit(5);
				}
				syscall_result = process_req(current, shared_mem_region, tun_name);
				__sync_synchronize();
				shared_mem_region[2] = 1;
				ctrtool_exit(syscall_result);
				while (1) ;
			} else {
				int w_stat = 0x100;
				long w_term = waitpid(child_pid, &w_stat, 0);
				if (w_term != child_pid) {
					perror("waitpid");
					return 2;
				}
				if (WIFEXITED(w_stat)) {
					if (shared_mem_region[2] == 1) {
						__sync_synchronize();
						errno = shared_mem_region[1];
						switch (WEXITSTATUS(w_stat)) {
							case 0:
								out_fd = shared_mem_region[0];
								break;
							case 1:
								perror("Failed to open root directory");
								return 2;
							case 2:
								perror("Failed to create socket");
								return 2;
							case 3:
								perror("NS_GET_USERNS");
								return 2;
							case 4:
								perror("CLONE_NEWUSER");
								return 2;
							case 5:
								perror("setns");
								return 2;
							default:
								perror("Failed to create file descriptor");
								return 2;
						}
					} else {
						fprintf(stderr, "Sync failure\n");
						return 2;
					}
				} else {
					fprintf(stderr, "Process terminated with %d\n", (int)(WIFSIGNALED(w_term) ? WTERMSIG(w_term) : 0));
					return 2;
				}
			}
			if (munmap(shared_mem_region, 4096)) {
				perror("munmap");
				return 2;
			}
			close(ns_fd);
		} else {
			int mem_record[2] = {-1, 1};
			if (process_req(current, mem_record, tun_name)) {
				perror("Failed to create file descriptor");
				return 2;
			}
			out_fd = mem_record[0];
		}
		if (fcntl(out_fd, F_GETFD, 0) < 0) {
			perror("fcntl");
			return 2;
		}
		char env_var_name[60] = {0};
		char env_var_value[15] = {0};
		if (snprintf(env_var_name, sizeof(env_var_name), "CTRTOOL_NS_OPEN_FILE_FD_%lu", (unsigned long) i) <= 0) {
			perror("snprintf");
			return 2;
		}
		if (snprintf(env_var_value, sizeof(env_var_value), "%d", out_fd) <= 0) {
			perror("snprintf");
			return 2;
		}
		if (setenv(env_var_name, env_var_value, 1)) {
			perror("setenv");
			return 2;
		}
	}
	execvp(argv[optind], &argv[optind]);
	perror("execvp()");
	return 127;
}
