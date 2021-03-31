#include <stdint.h>
#include <stdlib.h>
#define CTRTOOL_RELAY_SIZEOF(s) (sizeof(struct ctrtool_relay) + (s)->buffer_size)
#define CTRTOOL_RELAY_DATA(s) (&((char *)(s))[sizeof(struct ctrtool_relay)])
#define CTRTOOL_RELAY_STATE_START 1
#define CTRTOOL_RELAY_STATE_INPUT_EOF 2
#define CTRTOOL_RELAY_STATE_TERMINATED 3
void ctrtool_memcpy_or_memmove(void *dst, const void *src, ssize_t length);
struct ctrtool_relay *ctrtool_relay_new(int in_fd, int out_fd, size_t buffer_size, int ignore_eof);
int ctrtool_relay_consume(struct ctrtool_relay *state);
int ctrtool_relay_release(struct ctrtool_relay *state);
void ctrtool_relay_destroy(struct ctrtool_relay *state);
int ctrtool_relay_can_poll_in(const struct ctrtool_relay *state);
int ctrtool_relay_can_poll_out(const struct ctrtool_relay *state);
struct ctrtool_relay {
	int in_fd;
	int out_fd;
	uint8_t state;
	unsigned int ignore_eof:1;
	unsigned int in_blocking:1;
	unsigned int out_blocking:1;
	size_t buffer_size;
	size_t buffer_ptr;
};
