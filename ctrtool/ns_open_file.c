#define _GNU_SOURCE
#include "ctrtool-common.h"
#include "ctrtool_options.h"
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
#include <netinet/tcp.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <sys/un.h>
#include <stddef.h>
#define CTRTOOL_NS_OPEN_FILE_MOUNT 'm'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_SOCKET 'n'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_TUNTAP 'T'
#define CTRTOOL_NS_OPEN_FILE_NORMAL 'f'
struct ns_open_file_req {
	int type;
	unsigned enter_userns:1;
	unsigned anon_netns:1;
	unsigned set_reuseaddr_or_tap:1;
	unsigned set_reuseport_or_no_pi:1;
	unsigned set_freebind:1;
	unsigned set_transparent:1;
	unsigned set_defer_accept:1;
	unsigned set_v6only:2;
	unsigned set_nodelay:1;
	unsigned use_openat2:1;
	unsigned have_open_flags:1;
	unsigned ns_path_is_register:1;
	unsigned store_result_in_register:1;
	unsigned inhibit_setenv:1;
	unsigned register_is_dirfd:1;
	const char *ns_path;
	const char *file_path;
	struct open_how openat2_how;
	int sock_domain; /* or dir fd for mount namespace */
	int sock_type;
	int sock_protocol;
	int listen_backlog;
	int ns_path_register;
	int fd_result_register;
	struct sockaddr *bind_address;
	socklen_t bind_address_len;
	char *scope_id_name;
};
static struct ctrtool_opt_element domain_values[] = {
	{.name = "inet", .value = {.value = AF_INET}},
	{.name = "inet6", .value = {.value = AF_INET6}},
	{.name = "netlink", .value = {.value = AF_NETLINK}},
	{.name = "packet", .value = {.value = AF_PACKET}},
	{.name = "unix", .value = {.value = AF_UNIX}},
	{.name = "vsock", .value = {.value = AF_VSOCK}},
};
static struct ctrtool_opt_element type_values[] = {
	{.name = "dgram", .value = {.value = SOCK_DGRAM}},
	{.name = "dgram_nb", .value = {.value = SOCK_DGRAM|SOCK_NONBLOCK}},
	{.name = "raw", .value = {.value = SOCK_RAW}},
	{.name = "raw_nb", .value = {.value = SOCK_RAW|SOCK_NONBLOCK}},
	{.name = "seqpacket", .value = {.value = SOCK_SEQPACKET}},
	{.name = "seqpacket_nb", .value = {.value = SOCK_SEQPACKET|SOCK_NONBLOCK}},
	{.name = "stream", .value = {.value = SOCK_STREAM}},
	{.name = "stream_nb", .value = {.value = SOCK_STREAM|SOCK_NONBLOCK}},
	{.name = "tcp", .value = {.value = SOCK_STREAM}},
	{.name = "tcp_nb", .value = {.value = SOCK_STREAM|SOCK_NONBLOCK}},
	{.name = "udp", .value = {.value = SOCK_DGRAM}},
	{.name = "udp_nb", .value = {.value = SOCK_DGRAM|SOCK_NONBLOCK}},
};
static struct ctrtool_opt_element protocol_values[] = {
	{.name = "icmp", .value = {.value = IPPROTO_ICMP}},
	{.name = "ip", .value = {.value = IPPROTO_IP}},
	{.name = "ipv6", .value = {.value = IPPROTO_IPV6}},
	{.name = "tcp", .value = {.value = IPPROTO_TCP}},
	{.name = "udp", .value = {.value = IPPROTO_UDP}},
};
static struct ctrtool_opt_element dir_values[] = {
	{.name = "cwd", .value = {.value = AT_FDCWD}}
};
static struct ctrtool_opt_element open_values[] = {
	{.name = "append", .value = {.value = O_APPEND}},
	{.name = "async", .value = {.value = O_ASYNC}},
	{.name = "creat", .value = {.value = O_CREAT}},
	{.name = "create", .value = {.value = O_CREAT}},
	{.name = "direct", .value = {.value = O_DIRECT}},
	{.name = "directory", .value = {.value = O_DIRECTORY}},
	{.name = "dsync", .value = {.value = O_DSYNC}},
	{.name = "excl", .value = {.value = O_EXCL}},
	{.name = "noatime", .value = {.value = O_NOATIME}},
	{.name = "noctty", .value = {.value = O_NOCTTY}},
	{.name = "nofollow", .value = {.value = O_NOFOLLOW}},
	{.name = "nonblock", .value = {.value = O_NONBLOCK}},
	{.name = "path", .value = {.value = O_PATH}},
	{.name = "rdonly", .value = {.value = O_RDONLY}},
	{.name = "rdwr", .value = {.value = O_RDWR}},
	{.name = "sync", .value = {.value = O_SYNC}},
	{.name = "tmpfile", .value = {.value = O_TMPFILE}},
	{.name = "trunc", .value = {.value = O_TRUNC}},
	{.name = "wronly", .value = {.value = O_WRONLY}}
};
static struct ctrtool_opt_element resolve_values[] = {
	{.name = "beneath", .value = {.value = RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS}},
	{.name = "beneath_magiclinks", .value = {.value = RESOLVE_BENEATH}},
	{.name = "in_root", .value = {.value = RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS}},
	{.name = "in_root_magiclinks", .value = {.value = RESOLVE_IN_ROOT}},
	{.name = "no_magiclinks", .value = {.value = RESOLVE_NO_MAGICLINKS}},
	{.name = "no_symlinks", .value = {.value = RESOLVE_NO_SYMLINKS}},
	{.name = "no_xdev", .value = {.value = RESOLVE_NO_XDEV}}
};
#define NR_REGS 8
static int process_req(struct ns_open_file_req *req_text, int *result_fd, const char *tun_name, const int *register_list) {
	long _f = -1L;
	const char *req_file_path = req_text->file_path;
	if (!req_file_path) {
		req_file_path = "/";
	}
	struct open_how new_open_how = {0};
	new_open_how.flags = (req_text->use_openat2 || req_text->have_open_flags) ? req_text->openat2_how.flags : (O_RDONLY|O_PATH|O_DIRECTORY);
#ifdef O_LARGEFILE
	new_open_how.flags |= O_LARGEFILE;
#endif
	new_open_how.mode = (new_open_how.flags & (O_CREAT|O_TMPFILE)) ? req_text->openat2_how.mode : 0;
	new_open_how.resolve = req_text->openat2_how.resolve;
	int x_dir_fd = req_text->sock_domain;
	if (req_text->ns_path_is_register && req_text->register_is_dirfd) {
		int reg_num = req_text->ns_path_register;
		if ((reg_num < 0) || (reg_num >= NR_REGS)) {
			result_fd[0] = -1;
			result_fd[1] = ERANGE;
			return 1;
		}
		x_dir_fd = register_list[reg_num];
	}
	switch (req_text->type) {
		case CTRTOOL_NS_OPEN_FILE_MOUNT:
			if (req_text->use_openat2) {
				_f = ctrtool_syscall(CTRTOOL_SYS_openat2, x_dir_fd, req_file_path, &new_open_how, sizeof(new_open_how), 0, 0);
			} else {
				_f = ctrtool_syscall(SYS_openat, x_dir_fd, req_file_path, new_open_how.flags, new_open_how.mode, 0, 0);
			}
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
#if 0
			/* Might be a good safety thing but it will break socketbox-preload. */
			if (unshare(CLONE_FILES)) {
				result_fd[0] = -1;
				result_fd[1] = errno;
				return 2;
			}
#endif
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
			if (req_text->set_defer_accept) {
				if (setsockopt(_f, SOL_TCP, TCP_DEFER_ACCEPT, &one, sizeof(one))) goto close_f_fail;
			}
			int sopt_val = 1;
			switch (req_text->set_v6only) {
				case 1:
					sopt_val = 0;
					/* fallthrough */
				case 2:
					if (setsockopt(_f, SOL_IPV6, IPV6_V6ONLY, &sopt_val, sizeof(sopt_val))) goto close_f_fail;
					break;
			}
			if (req_text->set_nodelay) {
				if (setsockopt(_f, SOL_TCP, TCP_NODELAY, &one, sizeof(one))) goto close_f_fail;
			}
			if (req_text->bind_address) {
				if (req_text->bind_address_len == sizeof(struct sockaddr_in6)) {
					if (req_text->scope_id_name) {
#ifdef CTRTOOL_USE_IF_NAMETOINDEX
						unsigned int scope_index = if_nametoindex(req_text->scope_id_name);
						if (!scope_index) goto close_f_fail;
#else
						struct ifreq ifr = {0};
						strncpy(ifr.ifr_name, req_text->scope_id_name, sizeof(ifr.ifr_name)-1);
						if (ioctl(_f, SIOCGIFINDEX, &ifr)) goto close_f_fail;
						unsigned int scope_index = ifr.ifr_ifindex;
#endif
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
#define OPTARG_PRESET_V(v) ctrtool_options_parse_arg_int_with_preset(optarg, v, sizeof(v)/sizeof(v[0]), NULL, 0)
int ctr_scripts_ns_open_file_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	struct ctrtool_arraylist things_to_add = {0};
	things_to_add.elem_size = sizeof(struct ns_open_file_req);
	struct ns_open_file_req *current = NULL;
	const char *tun_name = "/dev/net/tun";
	int opt = 0;
	uint64_t i_offset = 0;
	const char *valid_modes = "";
	int *register_list = malloc(sizeof(int) * NR_REGS);
	ctrtool_assert(register_list);
	memset(register_list, 255, sizeof(int) * NR_REGS);
	while ((opt = getopt(argc, argv, "+mnTUM:N:d:t:p:l:4:6:z:fo:A2O:R:P:L:s:i:")) > 0) {
		char *d_optarg = NULL;
		switch (opt) {
			case 'm':
			case 'n':
			case 'T':
			case 'f':
				if (ctrtool_arraylist_expand_s(&things_to_add, NULL, 10, (void **) &current)) {
					perror("ctrtool_arraylist_expand");
					return 1;
				}
				current->type = opt;
				current->sock_domain = (opt == 'm') ? AT_FDCWD : AF_INET6;
				current->sock_type = SOCK_STREAM;
				current->sock_protocol = 0;
				current->openat2_how.mode = 0600;
				break;
			case 'U':
				if (!current) goto no_opt;
				current->enter_userns = 1;
				break;
			case 'M':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'T':
						tun_name = optarg;
						break;
					case 'm':
						if (1) {
							int c = optarg[0];
							if ((c >= '0') && (c <= '9')) {
								current->openat2_how.mode = strtoul(optarg, NULL, 8);
							} else {
								fprintf(stderr, "Invalid mode %s\n", optarg);
								return 1;
							}
						}
						break;
				}
				break;
			case 'N':
				if (!current) goto no_opt;
				current->ns_path = optarg;
				break;
			case 'd':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'n':
						current->sock_domain = ctrtool_options_parse_arg_int_with_preset(optarg, domain_values, sizeof(domain_values)/sizeof(domain_values[0]), NULL, 0);
						break;
					case 'm':
						switch(optarg[0]) {
							case ':':
							case '/':
								if (ctrtool_read_fd_env_spec(optarg, 1, &current->sock_domain)) {
									return 1;
								}
								break;
							default:
								current->sock_domain = ctrtool_options_parse_arg_int_with_preset(optarg, dir_values, sizeof(dir_values)/sizeof(dir_values[0]), NULL, 0);
								break;
						}
						break;
					default:
						fprintf(stderr, "-d may only be used with -m or -n\n");
						return 1;
				}
				break;
			case 't':
				if (!current) goto no_opt;
				current->sock_type = ctrtool_options_parse_arg_int_with_preset(optarg, type_values, sizeof(type_values)/sizeof(type_values[0]), NULL, 0);
				break;
			case 'p':
				if (!current) goto no_opt;
				current->sock_protocol = ctrtool_options_parse_arg_int_with_preset(optarg, protocol_values, sizeof(protocol_values)/sizeof(protocol_values[0]), NULL, 0);
				break;
			case 'l':
				if (!current) goto no_opt;
				current->listen_backlog = atoi(optarg);
				break;
			case 'A':
				if (!current) goto no_opt;
				if (current->type == 'n') {
					current->anon_netns = 1;
				} else {
					fprintf(stderr, "-A may only be used with -n\n");
					return 1;
				}
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
							case 'd':
								current->set_defer_accept = 1;
								break;
							case 'o':
								current->set_v6only = 2;
								break;
							case 'O':
								current->set_v6only = 1;
								break;
							case 'e':
								current->set_nodelay = 1;
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
					if (!result) goto no_mem;
					result->sin_family = AF_INET;
					result->sin_port = port_part_n;
					if (inet_pton(AF_INET, addr_part, &result->sin_addr) != 1) {
						goto no_addr_part;
					}
					current->bind_address = (struct sockaddr *) result;
					current->bind_address_len = sizeof(struct sockaddr_in);
				} else {
					struct sockaddr_in6 *result = calloc(sizeof(struct sockaddr_in6), 1);
					if (!result) goto no_mem;
					result->sin6_family = AF_INET6;
					result->sin6_port = port_part_n;
					if (inet_pton(AF_INET6, addr_part, &result->sin6_addr) != 1) {
						goto no_addr_part;
					}
					if (numeric_scope_id) {
						if (!scope_id_part) goto no_addr_part;
						result->sin6_scope_id = strtoul(scope_id_part, NULL, 0);
					}
					current->bind_address = (struct sockaddr *) result;
					current->bind_address_len = sizeof(struct sockaddr_in6);
					if (scope_id_part) {
						current->scope_id_name = strdup(scope_id_part);
						if (!current->scope_id_name) goto no_mem;
					}
				}
				break;
				/* FIXME: implement -z (arbitrary hex string as socket address, with domain included) */
			case 'o':
				i_offset = strtoull(optarg, NULL, 0);
				break;
			case 'O':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'm':
						current->openat2_how.flags |= OPTARG_PRESET_V(open_values);
						current->have_open_flags = 1;
						break;
					default:
						valid_modes = "-m";
						goto invalid_mode;
				}
				break;
			case 'R':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'm':
						current->openat2_how.resolve |= OPTARG_PRESET_V(resolve_values);
						current->have_open_flags = 1;
						current->use_openat2 = 1;
						break;
					default:
						valid_modes = "-m";
						goto invalid_mode;
				}
				break;
			case '2':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'm':
						current->have_open_flags = 1;
						current->use_openat2 = 1;
						break;
					default:
						valid_modes = "-m";
						goto invalid_mode;
				}
				break;
			case 'P':
				if (!current) goto no_opt;
				switch (current->type) {
					case 'm':
						current->file_path = optarg;
						current->have_open_flags = 1;
						break;
					case 'n':
						if (current->bind_address) goto already_address;
						size_t unix_path_len = strnlen(optarg, sizeof(((struct sockaddr_un *) 0)->sun_path)+1);
						if (unix_path_len > sizeof(((struct sockaddr_un *) 0)->sun_path)) {
							fprintf(stderr, "Unix domain socket path too long\n");
							return 1;
						}
						struct sockaddr_un *unix_path = calloc(sizeof(struct sockaddr_un), 1);
						if (!unix_path) goto no_mem;
						unix_path->sun_family = AF_UNIX;
						memcpy(unix_path->sun_path, optarg, unix_path_len);
						if (unix_path->sun_path[0] == '@') unix_path->sun_path[0] = '\0';
						current->bind_address = (struct sockaddr *) unix_path;
						current->bind_address_len = unix_path_len + offsetof(struct sockaddr_un, sun_path);
						break;
					default:
						valid_modes = "-m or -n";
						goto invalid_mode;
				}
				break;
			case 'L':
			case 's':
			case 'i':
				if ((opt == 'L') && current) {
					fprintf(stderr, "-L must be before -m, -n, -T, and -f\n");
					return 1;
				}
				if ((opt == 'i') && !current) goto no_opt;
				if ((opt == 's') && !current) goto no_opt;
				if (1) {
					d_optarg = ctrtool_strdup(optarg);
					char *reg_part_b = strchr(d_optarg, ',');
					if (!reg_part_b) {
						if (opt == 'L') {
							fprintf(stderr, "Missing specification for register load\n");
							return 1;
						}
					} else {
						reg_part_b[0] = 0;
					}
					int reg_num = atoi(d_optarg);
					if ((reg_num < 0) || (reg_num >= NR_REGS)) {
						fprintf(stderr, "Invalid register %d\n", reg_num);
						return 1;
					}
					char *arg_part = reg_part_b ? &reg_part_b[1] : "";
					switch (opt) {
						case 'L':
							/* "Load" the register with the specified value. */
							if (ctrtool_read_fd_env_spec(arg_part, 1, &register_list[reg_num])) {
								return 1;
							}
							break;
						case 's':
							if (current->store_result_in_register) {
								fprintf(stderr, "Multiple use of -s not allowed\n");
								return 1;
							}
							current->store_result_in_register = 1;
							current->fd_result_register = reg_num;
							/* 'i' flag inhibits setting the CTRTOOL_NS_OPEN_FILE_FD_n variable */
							while (*arg_part) {
								switch (*arg_part) {
									case 'i':
										current->inhibit_setenv = 1;
										break;
									default:
										fprintf(stderr, "Invalid flag '%c' for -s\n", *arg_part);
										return 1;
								}
								arg_part++;
							}
							break;
						case 'i':
							if (current->ns_path_is_register) {
								fprintf(stderr, "Multiple use of -i not allowed\n");
								return 1;
							}
							current->ns_path_is_register = 1;
							current->ns_path_register = reg_num;
							/* 'd' to specify that it's a directory descriptor for openat(). */
							/* 'n' to specify that it's a namespace (default) */
							while (*arg_part) {
								switch (*arg_part) {
									case 'd':
										current->register_is_dirfd = 1;
										break;
									case 'n':
										current->register_is_dirfd = 0;
										break;
									default:
										fprintf(stderr, "Invalid flag '%c' for -i\n", *arg_part);
										return 1;
								}
								arg_part++;
							}
							if (!current->register_is_dirfd) {
								current->ns_path = "";
							}
							break;
					}
				}
				break;
			default:
				return 1;
		}
		continue;
no_opt:
		fprintf(stderr, "-%c may not be used before -m, -n, -T, or -f\n", opt);
no_mem:
		return 1;
invalid_mode:
		fprintf(stderr, "-%c may only be used with %s\n", opt, valid_modes);
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
		if (current->ns_path || current->anon_netns) {
			if (current->type == 'f') {
				out_fd = open(current->ns_path, O_RDONLY|O_NOCTTY);
				if (out_fd < 0) {
					perror("open");
					return 2;
				}
				goto end_f;
			}
			int *shared_mem_region = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
			if (shared_mem_region == MAP_FAILED) {
				perror("mmap");
				return 2;
			}
			shared_mem_region[0] = -1;
			int ns_fd = -1;
			if (current->ns_path) {
				if (current->ns_path_is_register && !current->register_is_dirfd) {
					int r = current->ns_path_register;
					ctrtool_assert((r >= 0) && (r < NR_REGS));
					ns_fd = fcntl(register_list[r], F_DUPFD_CLOEXEC, 3);
				} else {
					ns_fd = open(current->ns_path, O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC);
				}
				if (ns_fd < 0) {
					perror("open namespace");
					return 2;
				}
				struct statfs ns_fd_fs = {0};
				if (fstatfs(ns_fd, &ns_fd_fs)) {
					perror("statfs");
					return 2;
				}
				if (ns_fd_fs.f_type != NSFS_MAGIC) {
					fprintf(stderr, "Namespace file %s is not NSFS_MAGIC\n", current->ns_path);
					return 2;
				}
			}
			long child_pid = ctrtool_clone_onearg(CLONE_FILES|SIGCHLD);
			if (child_pid < 0) {
				errno = -child_pid;
				perror("clone()");
				return 2;
			}
			if (child_pid == 0) {
				int dumpable_set = 0;
				if (current->ns_path) {
					if (current->enter_userns ^ current->anon_netns) { /* -A or -U, but not neither or -AU */
						if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
							shared_mem_region[0] = -1;
							shared_mem_region[1] = errno;
							__sync_synchronize();
							shared_mem_region[2] = 1;
							ctrtool_exit(255);
						}
						dumpable_set = 1;
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
					} else if (current->anon_netns && current->enter_userns) {
						if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
							shared_mem_region[0] = -1;
							shared_mem_region[1] = errno;
							__sync_synchronize();
							shared_mem_region[2] = 1;
							ctrtool_exit(255);
						}
						dumpable_set = 1;
						if (setns(ns_fd, CLONE_NEWUSER)) {
							shared_mem_region[0] = -1;
							shared_mem_region[1] = errno;
							__sync_synchronize();
							shared_mem_region[2] = 1;
							ctrtool_exit(4);
						}
					}
				}
				if ((!dumpable_set) && (current->type == CTRTOOL_NS_OPEN_FILE_MOUNT)) {
					if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
						shared_mem_region[0] = -1;
						shared_mem_region[1] = errno;
						__sync_synchronize();
						shared_mem_region[2] = 1;
						ctrtool_exit(255);
					}
				}
				long syscall_result;
				if (current->anon_netns) {
					syscall_result = ctrtool_syscall(SYS_unshare, CLONE_NEWNET, 0, 0, 0, 0, 0);
				} else {
					syscall_result = ctrtool_syscall(SYS_setns, ns_fd, ((current->type == CTRTOOL_NS_OPEN_FILE_MOUNT) ? CLONE_NEWNS : CLONE_NEWNET), 0, 0, 0, 0);
				}
				if (syscall_result < 0) {
					shared_mem_region[0] = -1;
					shared_mem_region[1] = -syscall_result;
					__sync_synchronize();
					shared_mem_region[2] = 1;
					ctrtool_exit(5);
				}
				syscall_result = process_req(current, shared_mem_region, tun_name, register_list);
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
								fprintf(stderr, "Failed to open %s in mount namespace: %s\n", current->file_path ? current->file_path : "root directory", strerror(errno));
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
			if (process_req(current, mem_record, tun_name, register_list)) {
				errno = mem_record[1];
				perror("Failed to create file descriptor");
				return 2;
			}
			out_fd = mem_record[0];
		}
end_f:
		;int fcntl_flags = fcntl(out_fd, F_GETFD, 0);
		if (fcntl_flags < 0) {
			perror("fcntl");
			return 2;
		}
		if (current->inhibit_setenv) {
			if (fcntl(out_fd, F_SETFD, (fcntl_flags | FD_CLOEXEC))) {
				perror("fcntl");
				return 2;
			}
		} else {
			if (fcntl(out_fd, F_SETFD, (fcntl_flags & ~FD_CLOEXEC))) {
				perror("fcntl");
				return 2;
			}
		}
		char env_var_name[60] = {0};
		char env_var_value[15] = {0};
		if (snprintf(env_var_name, sizeof(env_var_name), "CTRTOOL_NS_OPEN_FILE_FD_%llu", (unsigned long long) (i_offset + (uint64_t) i)) <= 0) {
			perror("snprintf");
			return 2;
		}
		if (snprintf(env_var_value, sizeof(env_var_value), "%d", current->inhibit_setenv ? -1 : out_fd) <= 0) {
			perror("snprintf");
			return 2;
		}
		if (setenv(env_var_name, env_var_value, 1)) {
			perror("setenv");
			return 2;
		}
		if (current->store_result_in_register) {
			int reg_num = current->fd_result_register;
			ctrtool_assert((reg_num >= 0) && (reg_num < NR_REGS));
			register_list[reg_num] = out_fd;
		}
	}
	execvp(argv[optind], &argv[optind]);
	perror("execvp()");
	return 127;
}
