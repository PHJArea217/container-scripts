#include <stdint.h>
#include <netinet/ip6.h>
struct bind_anywhere_config_line {
	struct in6_addr target_addr;
	uint16_t target_port_number;
	uint8_t c_flags;
	uint8_t flags;
	uint32_t pid_or_pidfd;
	uint32_t fd_number;
	uint64_t inode_number;
};
#define BIND_ANYWHERE_CFLAGS_TCP 0
#define BIND_ANYWHERE_CFLAGS_UDP 1
#define BIND_ANYWHERE_CFLAGS_IS_IPV4 16

#define BIND_ANYWHERE_FLAGS_IS_PIDFD 1
#define BIND_ANYWHERE_FLAGS_CHECK_INODE_NUMBER 2
#define BIND_ANYWHERE_FLAGS_HAS_INODE_NUMBER 4
void bind_anywhere_parse_config(const char *config);
int bind_anywhere_find_config_for_address(struct bind_anywhere_config_line *line);
