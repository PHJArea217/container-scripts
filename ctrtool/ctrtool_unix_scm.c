#include "ctrtool-common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
int ctrtool_unix_scm_send(int sock_fd, int fd) {
	union {
		struct cmsghdr cmsg;
		char space[CMSG_SPACE(sizeof(int))];
	} cmsg_rawdata = {};
	struct msghdr mh = {};
	struct iovec data = {"\0", 1};
	mh.msg_name = NULL;
	mh.msg_namelen = 0;
	mh.msg_iov = &data;
	mh.msg_iovlen = 1;
	mh.msg_control = &cmsg_rawdata;
	mh.msg_controllen = sizeof(cmsg_rawdata.space);
	mh.msg_flags = 0;
	struct cmsghdr *hdr = CMSG_FIRSTHDR(&mh);
	hdr->cmsg_level = SOL_SOCKET;
	hdr->cmsg_type = SCM_RIGHTS;
	hdr->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(hdr), &fd, sizeof(int));
	if (sendmsg(sock_fd, &mh, 0) != 1) {
		return -1;
	}
	return 0;
}
struct ctrtool_scm_data {
	char buf[128];
	char cmsg_buf[1280];
};
int ctrtool_unix_scm_recv(int sock_fd) {
	while (1) {
		struct ctrtool_scm_data temp_data = {};
		struct msghdr recv_hdr = {};
		struct iovec recv_iov = {temp_data.buf, sizeof(temp_data.buf)};
		recv_hdr.msg_name = NULL;
		recv_hdr.msg_namelen = 0;
		recv_hdr.msg_iov = &recv_iov;
		recv_hdr.msg_iovlen = 1;
		recv_hdr.msg_control = temp_data.cmsg_buf;
		recv_hdr.msg_controllen = sizeof(temp_data.cmsg_buf);
		recv_hdr.msg_flags = 0;
		ssize_t recvmsg_result = recvmsg(sock_fd, &recv_hdr, 0);
		if (recvmsg_result < 0) {
			if (errno == EINTR) continue;
		}
		if (recvmsg_result == 0) {
			errno = ENODATA;
			return -1;
		}
		int current_fd = -1;
		int has_fd = 0;
		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&recv_hdr); cmsg; cmsg = CMSG_NXTHDR(&recv_hdr, cmsg)) {
			if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_RIGHTS)) {
				int *fd_list = (int *) CMSG_DATA(cmsg);
				socklen_t f_len = cmsg->cmsg_len;
				if (f_len <= CMSG_LEN(0)) continue;
				int nr_fds = (f_len - CMSG_LEN(0)) / sizeof(int);
				if ((nr_fds < 0) || (nr_fds > 255)) continue;
				for (int i = 0; i < nr_fds; i++) {
					/* FIXME: In the future this function will support receiving multiple
					 * file descriptors. Currently, we only need to support one. */
					int fd_num = -1;
					memcpy(&fd_num, &fd_list[i], sizeof(int));
					if (has_fd) {
						close(fd_num);
					} else {
						if (fd_num >= 0) {
							current_fd = fd_num;
							has_fd = 1;
						}
					}
				}
			}
		}
		if (!has_fd) {
			/* Not looping. Not intended to be as robust compared to socketbox's SCM_RIGHTS receive function. */
			errno = ENODATA;
			return -1;
		}
		return current_fd;
	}
}
