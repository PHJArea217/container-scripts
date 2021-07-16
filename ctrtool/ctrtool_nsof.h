#ifdef CTRTOOL_CONFIG_HAVE_LINUX_OPENAT2
#include <linux/openat2.h>
#else
struct open_how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};
#define RESOLVE_NO_XDEV 1
#define RESOLVE_NO_MAGICLINKS 2
#define RESOLVE_NO_SYMLINKS 4
#define RESOLVE_BENEATH 8
#define RESOLVE_IN_ROOT 16
#endif
#include <sys/un.h>
#include <stddef.h>
#include <sys/socket.h>
#define CTRTOOL_NS_OPEN_FILE_MOUNT 'm'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_SOCKET 'n'
#define CTRTOOL_NS_OPEN_FILE_NETWORK_TUNTAP 'T'
#define CTRTOOL_NS_OPEN_FILE_NORMAL 'f'
#define CTRTOOL_NS_OPEN_FILE_SPECIAL 'I'
#define CTRTOOL_NSOF_SPECIAL_MEMFD 0x101
#define CTRTOOL_NSOF_SPECIAL_MEMFD_SEAL 0x102
#define CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_READ 0x201
#define CTRTOOL_NSOF_SPECIAL_POPEN_PIPE_WRITE 0x202
#define CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDIN 0x211
#define CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_STDOUT 0x212
#define CTRTOOL_NSOF_SPECIAL_POPEN_SOCK_BOTH 0x213
#define CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD 0x221
#define CTRTOOL_NSOF_SPECIAL_POPEN_MEMFD_SEAL 0x222
#define CTRTOOL_NSOF_SPECIAL_PTSLAVE 0x301
#define CTRTOOL_NSOF_SPECIAL_NO_FD_BIT 0x10000
#define CTRTOOL_NSOF_SPECIAL_POLL 0x10101
#define CTRTOOL_NSOF_SPECIAL_IFNE 0x10102
#define CTRTOOL_NSOF_SPECIAL_CONNECT 0x10103
#define CTRTOOL_NSOF_SPECIAL_CONNECT_UNIX_PATH 0x10104
#define CTRTOOL_NSOF_SPECIAL_SCM_RIGHTS_SEND_ONE 0x10201
#define CTRTOOL_NSOF_SPECIAL_SCM_RIGHTS_RECV_ONE 0x401
#define CTRTOOL_NSOF_SPECIAL_MAJOR_MASK 0xfff00
#define CTRTOOL_NSOF_SPECIAL_MAJOR_MEMFD 0x100
#define CTRTOOL_NSOF_SPECIAL_MAJOR_POPEN 0x200
#define CTRTOOL_NSOF_SPECIAL_MAJOR_MISC 0x300
#define CTRTOOL_NSOF_SPECIAL_MAJOR_MISC_NO_FD 0x10100
#define CTRTOOL_NSOF_SPECIAL_MAJOR_SCM_RIGHTS_RECV 0x400
#define CTRTOOL_NSOF_SPECIAL_MAJOR_SCM_RIGHTS_SEND 0x10200
#define CTRTOOL_NSOF_SPECIAL_MINOR_MASK 0xff
struct ns_open_file_req {
	int type;
	unsigned int i_subtype;
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
	const char *file_path; /* or sh -c command for -I popen_* */
	struct open_how openat2_how;
	int sock_domain; /* or dir fd for mount namespace, or unix path fd for -I connect_unix_path */
	int sock_type;
	int sock_protocol;
	int listen_backlog;
	int ns_path_register; /* or register containing fd for fd operation */
	int fd_result_register;
	struct sockaddr *bind_address;
	socklen_t bind_address_len;
	char *scope_id_name;
};
int ctrtool_nsof_process_special(struct ns_open_file_req *req, const int *register_list);
