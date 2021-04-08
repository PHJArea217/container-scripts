#include "ctrtool-common.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include "ctrtool_relay.h"
void ctrtool_memcpy_or_memmove(void *dst, const void *src, ssize_t length) {
	ptrdiff_t diffs = ((char *) dst) - ((char *) src);
	if ((diffs >= length) || (diffs <= -length)) {
		memcpy(dst, src, length);
	} else {
		memmove(dst, src, length);
	}
}
struct ctrtool_relay *ctrtool_relay_new(int in_fd, int out_fd, size_t buffer_size, int ignore_eof) {
	int stdin_blocking = ctrtool_make_fd_nonblocking(in_fd, 1);
	if (stdin_blocking < 0) return NULL;
	int stdout_blocking = ctrtool_make_fd_nonblocking(out_fd, 1);
	if (stdout_blocking < 0) {
		ctrtool_make_fd_nonblocking(in_fd, stdin_blocking);
		return NULL;
	}
	struct ctrtool_relay *new_obj = calloc(buffer_size + sizeof(struct ctrtool_relay), 1);
	if (new_obj == NULL) {
		ctrtool_make_fd_nonblocking(out_fd, stdout_blocking);
		ctrtool_make_fd_nonblocking(in_fd, stdin_blocking);
		return NULL;
	}
	new_obj->in_fd = in_fd;
	new_obj->out_fd = out_fd;
	new_obj->state = CTRTOOL_RELAY_STATE_START;
	new_obj->buffer_size = buffer_size;
	new_obj->ignore_eof = !!ignore_eof;
	new_obj->in_blocking = !!stdin_blocking;
	new_obj->out_blocking = !!stdout_blocking;
	return new_obj;
}
int ctrtool_relay_consume(struct ctrtool_relay *state) {
	if (state->buffer_ptr >= state->buffer_size) {
		return 0;
	}
	if (state->state != CTRTOOL_RELAY_STATE_START) {
		return 0;
	}
	ssize_t n_read = read(state->in_fd, &CTRTOOL_RELAY_DATA(state)[state->buffer_ptr], state->buffer_size - state->buffer_ptr);
	if (n_read < 0) {
		if (errno == EAGAIN)
			return 0;
		if (state->buffer_ptr) {
			state->state = CTRTOOL_RELAY_STATE_INPUT_EOF;
		} else {
			state->state = CTRTOOL_RELAY_STATE_TERMINATED;
		}
		return -1;
	}
	if ((!state->ignore_eof) && (n_read == 0)) {
		if (state->buffer_ptr) {
			state->state = CTRTOOL_RELAY_STATE_INPUT_EOF;
		} else {
			state->state = CTRTOOL_RELAY_STATE_TERMINATED;
		}
		return 0;
	}
	size_t new_size = state->buffer_ptr + n_read;
	if (new_size > state->buffer_size) abort();
	state->buffer_ptr = new_size;
	return 0;
}
int ctrtool_relay_release(struct ctrtool_relay *state) {
	if (state->state == CTRTOOL_RELAY_STATE_TERMINATED) {
		return 0;
	}
	if (state->buffer_ptr == 0) return 0;
	ssize_t n_written = write(state->out_fd, CTRTOOL_RELAY_DATA(state), state->buffer_ptr);
	if (n_written <= 0) {
		if (errno == EAGAIN) {
			return 0;
		}
		state->buffer_ptr = 0;
		state->state = CTRTOOL_RELAY_STATE_TERMINATED;
		return -1;
	}
	if (n_written >= state->buffer_ptr) {
		if (state->state == CTRTOOL_RELAY_STATE_INPUT_EOF) {
			state->state = CTRTOOL_RELAY_STATE_TERMINATED;
		}
		state->buffer_ptr = 0;
	} else {
		state->buffer_ptr -= n_written;
		ctrtool_memcpy_or_memmove(CTRTOOL_RELAY_DATA(state), &CTRTOOL_RELAY_DATA(state)[n_written], state->buffer_ptr);
	}
	return 0;
}
void ctrtool_relay_destroy(struct ctrtool_relay *state) {
	ctrtool_make_fd_nonblocking(state->out_fd, state->out_blocking);
	ctrtool_make_fd_nonblocking(state->in_fd, state->in_blocking);
	free(state);
}
int ctrtool_relay_can_poll_in(const struct ctrtool_relay *state) {
	if (state->state != CTRTOOL_RELAY_STATE_START) return 0;
	if (state->buffer_ptr >= state->buffer_size) return 0;
	return 1;
}
int ctrtool_relay_can_poll_out(const struct ctrtool_relay *state) {
	if (state->state == CTRTOOL_RELAY_STATE_TERMINATED) {
		return 0;
	}
	return state->buffer_ptr > 0;
}
