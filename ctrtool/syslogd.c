#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
static int strbuf_append(char *buf, size_t max_len, size_t *current, const char *new_string) {
	if (*current >= max_len) {
		return -1;
	}
	const char *string_p = new_string;
	while (*string_p) {
		buf[(*current)++] = *(string_p++);
		if (*current >= max_len) {
			return -1;
		}
	}
	return 0;
}
static void msg_to_syslog(struct msghdr *input_msg, size_t returned_size, FILE *out_file, char *tmp_buf, size_t tmp_buf_size) {
	unsigned char *input_msg_buf = input_msg->msg_iov[0].iov_base;
//	write(2, input_msg_buf, 30);
	pid_t msg_pid = -1;
	uid_t msg_uid = -1;
	gid_t msg_gid = -1;
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(input_msg); cmsg; cmsg = CMSG_NXTHDR(input_msg, cmsg)) {
		if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_CREDENTIALS) && (cmsg->cmsg_len >= CMSG_LEN(sizeof(struct ucred)))) {
			struct ucred *creds = CMSG_DATA(cmsg);
			msg_pid = creds->pid;
			msg_uid = creds->uid;
			msg_gid = creds->gid;
			break;
		}
	}
	int level = 6;
	/* <NN>MMM DD HH:MM:SS */
	/* <N>MMM DD HH:MM:SS */
	if (returned_size >= 4) {
		if (input_msg_buf[0] == '<') {
			unsigned char first_digit = input_msg_buf[1];
			if ((first_digit >= '0') && (first_digit <= '9')) {
				level = first_digit - '0';
			} else if (first_digit == '-') {
				level = -1;
			} else {
				goto trim_done;
			}
			unsigned char second_digit = input_msg_buf[2];
			if ((second_digit >= '0') && (second_digit <= '9')) {
				if (level == -1) {
					level = '0' - second_digit;
				} else {
					level = 10 * level + (second_digit - '0');
				}
				if (input_msg_buf[3] == '>') {
					input_msg_buf += 4;
					returned_size -= 4;
				} else {
					goto trim_done;
				}
			} else if (second_digit == '>') {
				input_msg_buf += 3;
				returned_size -= 3;
			} else {
				goto trim_done;
			}
		}
	}
trim_done:
#define CHECK_CHAR_RANGE(b, i, l, u) ((b[i] >= (l)) && (b[i] <= (u)))
	if (returned_size >= 16) {
		if (!CHECK_CHAR_RANGE(input_msg_buf, 0, 'A', 'Z')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 1, 'a', 'z')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 2, 'a', 'z')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 3, ' ', ' ')) goto trim_done2;
		if (!((input_msg_buf[4] == ' ') || CHECK_CHAR_RANGE(input_msg_buf, 4, '1', '3'))) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 5, '0', '9')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 6, ' ', ' ')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 7, '0', '2')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 8, '0', '9')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 9, ':', ':')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 10, '0', '5')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 11, '0', '9')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 12, ':', ':')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 13, '0', '5')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 14, '0', '9')) goto trim_done2;
		if (!CHECK_CHAR_RANGE(input_msg_buf, 15, ' ', ' ')) goto trim_done2;
		input_msg_buf += 16;
		returned_size -= 16;
	}
trim_done2:
	memset(tmp_buf, 0, tmp_buf_size);
	size_t current_pos = 0;
	while (returned_size) {
		unsigned char current_char = *(input_msg_buf++);
		char output_buf[] = {0, 0, 0, 0, 0};
		returned_size--;
		if (current_char == '\\') {
			output_buf[0] = '\\';
			output_buf[1] = '\\';
		}
		if (current_char >= 127) goto all_three_octal;
		if (current_char < 32) {
			if (returned_size >= 1) {
				if (CHECK_CHAR_RANGE(input_msg_buf, 0, '0', '9')) goto all_three_octal;
			}
			if (current_char < 8) {
				output_buf[0] = '\\';
				output_buf[1] = current_char + '0';
			} else {
				output_buf[0] = '\\';
				output_buf[1] = (current_char >> 3) + '0';
				output_buf[2] = (current_char & 7) + '0';
			}
		} else {
			output_buf[0] = current_char;
		}
		goto all_three_octal_done;
all_three_octal:
		output_buf[0] = '\\';
		output_buf[1] = '0' + (current_char >> 6);
		output_buf[2] = '0' + ((current_char >> 3) & 7);
		output_buf[3] = '0' + (current_char & 7);
all_three_octal_done:
		if (strbuf_append(tmp_buf, tmp_buf_size - 1, &current_pos, output_buf)) {
			break;
		}
	}
//	puts(tmp_buf);
	struct tm u_time = {0};
	struct timespec my_time = {0, 0};
	clock_gettime(CLOCK_REALTIME, &my_time);
	gmtime_r(&my_time.tv_sec, &u_time);
	/* TODO error handling (e.g. if disk is full) */
	fprintf(out_file, "%04d-%02d-%02dT%02d:%02d:%02d.%09ld %lu,%lu,%lu %d %s\n",
			u_time.tm_year + 1900, u_time.tm_mon + 1, u_time.tm_mday,
			u_time.tm_hour, u_time.tm_min, u_time.tm_sec, my_time.tv_nsec,
			(unsigned long) msg_pid, (unsigned long) msg_uid, (unsigned long) msg_gid,
			level, tmp_buf);
	fflush(out_file);
}
int ctr_scripts_syslogd_main(int argc, char **argv) {
	ctrtool_clear_saved_argv();
	if (argc >= 2) {
		fprintf(stderr, "Command line arguments currently not supported.\n/dev/log socket on fd 0, writes log messages to stdout\n");
		return 1;
	}
	int recv_fd = 0;
	int one = 1;
	struct rlimit res_limits_orig = {0, 4096};
	if (prlimit(0, RLIMIT_NOFILE, NULL, &res_limits_orig)) {
		perror("getrlimit");
		return 1;
	}
	struct rlimit res_limits_capped = {0, res_limits_orig.rlim_max};
	if (setsockopt(recv_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) {
		perror("setsockopt");
		return 1;
	}
	char *common_buf = malloc(4096);
	if (!common_buf) {
		perror("malloc");
		return 1;
	}
	memset(common_buf, 0, 4096);
	void *tmp_buf = &common_buf[0];
	void *recv_buf = &common_buf[2048];
	void *recv_anc_buf = &common_buf[1536];
	int has_recvmsg_error = 0;
	int sock_type = 0;
	socklen_t sock_type_len = sizeof(int);
	if (getsockopt(recv_fd, SOL_SOCKET, SO_TYPE, &sock_type, &sock_type_len)) {
		perror("getsockopt");
		return 1;
	}
	if (sock_type_len != sizeof(int)) {
		perror("getsockopt");
		return 1;
	}
	while (1) {
		struct iovec m_iov = {recv_buf, 1024};
		struct msghdr m_h = {NULL, 0, &m_iov, 1, recv_anc_buf, 480, 0};
		if (prlimit(0, RLIMIT_NOFILE, &res_limits_capped, NULL)) {
			if (prlimit(0, RLIMIT_NOFILE, NULL, &res_limits_capped)) {
				perror("prlimit");
				break;
			}
			res_limits_capped.rlim_cur = 0;
			if (prlimit(0, RLIMIT_NOFILE, &res_limits_capped, NULL)) {
				perror("prlimit");
				break;
			}
		}
		ssize_t result = recvmsg(recv_fd, &m_h, 0);
		int saved_errno = errno;
		if (prlimit(0, RLIMIT_NOFILE, &res_limits_orig, NULL)) {
			if (prlimit(0, RLIMIT_NOFILE, NULL, &res_limits_orig)) {
				perror("prlimit");
				break;
			}
			res_limits_orig.rlim_cur = res_limits_orig.rlim_max;
			if (prlimit(0, RLIMIT_NOFILE, &res_limits_orig, NULL)) {
				perror("prlimit");
				break;
			}
		}
		errno = saved_errno;
		if (result < 0) {
			perror("recvmsg");
			if (has_recvmsg_error) break;
			has_recvmsg_error = 1;
			continue;
		} else {
			has_recvmsg_error = 0;
		}
		if (result == 0) {
			if (sock_type == SOCK_DGRAM) continue;
			free(common_buf);
			return 0;
		}
		else if (result > 1024) {
			continue;
		}
		msg_to_syslog(&m_h, result, stdout, tmp_buf, 1280);
	}
	free(common_buf);
	return -1;
}
