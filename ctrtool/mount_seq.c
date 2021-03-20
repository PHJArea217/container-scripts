#define _GNU_SOURCE
#include "ctrtool-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#define MOUNT_SEQ_CMD_MOUNT 'm'
#define MOUNT_SEQ_CMD_MKDIR 'D'
#define MOUNT_SEQ_CMD_UMOUNT 'u'
#define MOUNT_SEQ_CMD_SYSTEM 'S'
#define MOUNT_SEQ_CMD_CHDIR 'c'
#define MOUNT_SEQ_CMD_SYMLINK 'l'
struct mount_seq {
	char *target;
	uint8_t cmd;
	unsigned keep_going_if_fail:1;
	unsigned sync_after_operation:1;
	unsigned skip_target_symlink_check:1;
	union {
		struct {
			unsigned int flags;
			unsigned skip_source_symlink_check:1;
			unsigned mkdir_if_not_exist:1;
			unsigned make_file_if_not_exist:1;
			char *source;
			char *fstype;
			char *data;
		} mount_opts;
		struct {
			unsigned int flags;
			mode_t mode;
			unsigned no_error_if_exists:1;
			unsigned set_mode:1;
		} mkdir_opts;
		struct {
			unsigned int flags;
		} umount_opts;
		struct {
			unsigned int flags;
			unsigned int _padding;
			char *link_name;
		} symlink_opts;
	} opts;
};
static unsigned int flags_bitmap_mount[] = {
	/* a */ MS_NOATIME,
	/* b */ MS_BIND,
	/* c */ MS_RELATIME,
	/* d */ MS_NODEV,
	/* e */ MS_DIRSYNC,
	/* f */ 0,
	/* g */ 0,
	/* h */ MS_SHARED,
	/* i */ 0,
	/* j */ 0,
	/* k */ 0,
	/* l */ MS_SLAVE,
	/* m */ MS_MOVE,
	/* n */ 0,
	/* o */ MS_RDONLY,
	/* p */ MS_PRIVATE,
	/* q */ MS_SILENT,
	/* r */ MS_REMOUNT,
	/* s */ MS_NOSUID,
	/* t */ MS_STRICTATIME,
	/* u */ MS_UNBINDABLE,
	/* v */ MS_REC,
	/* w */ MS_SYNCHRONOUS,
	/* x */ MS_NOEXEC,
	/* y */ 0,
	/* z */ MS_LAZYTIME
};
static unsigned int flags_bitmap_umount[] = {
	/* a */ 0,
	/* b */ 0,
	/* c */ 0,
	/* d */ 0,
	/* e */ 0,
	/* f */ MNT_FORCE,
	/* g */ 0,
	/* h */ 0,
	/* i */ 0,
	/* j */ 0,
	/* k */ 0,
	/* l */ MNT_DETACH,
	/* m */ 0,
	/* n */ UMOUNT_NOFOLLOW,
	/* o */ 0,
	/* p */ 0,
	/* q */ 0,
	/* r */ 0,
	/* s */ 0,
	/* t */ 0,
	/* u */ 0,
	/* v */ 0,
	/* w */ 0,
	/* x */ MNT_EXPIRE,
	/* y */ 0,
	/* z */ 0
};
static unsigned int flags_bitmap_mkdir[] = {
	/* a */ 0,
	/* b */ 0,
	/* c */ 0,
	/* d */ 0,
	/* e */ 1,
	/* f */ 0,
	/* g */ 0,
	/* h */ 0,
	/* i */ 0,
	/* j */ 0,
	/* k */ 0,
	/* l */ 0,
	/* m */ 0,
	/* n */ 0,
	/* o */ 0,
	/* p */ 0,
	/* q */ 0,
	/* r */ 0,
	/* s */ 0,
	/* t */ 0,
	/* u */ 0,
	/* v */ 0,
	/* w */ 0,
	/* x */ 0,
	/* y */ 0,
	/* z */ 0
};
static unsigned int search_opts(const char *i_opt, const unsigned int *table, char *invalid_opt, int just_the_number) {
	if (invalid_opt) *invalid_opt = 0;
	if (just_the_number) {
		unsigned long val = strtoul(i_opt, NULL, 0);
		if (val >= 64) {
			if (invalid_opt) *invalid_opt = '?';
			return 0;
		}
		return 1ULL << val;
	}
	const char *o = i_opt;
	unsigned int result = 0;
	while (*o) {
		uint8_t opt = *o;
		if ((opt >= 'a') && (opt <= 'z')) {
			unsigned int flag = table[opt - 'a'];
			if (!flag) {
				if (invalid_opt) *invalid_opt = opt;
				return 0;
			}
			result |= flag;
		} else {
			if (invalid_opt) *invalid_opt = opt;
			return 0;
		}
		o++;
	}
	return result;
}
static int check_path_for_symlinks(const char *path, int may_make_dir) {
	/* FIXME: openat2() */
	size_t buf_len = strlen(path) + 1;
	char *buf = malloc(buf_len);
	memset(buf, 0, buf_len);
	const char *s_ptr = path;
	char *d_ptr = buf;
	while (*s_ptr) {
		if ((*s_ptr == '/') && (d_ptr != buf)) {
			struct stat st = {0};
			if (lstat(buf, &st)) {
				free(buf);
				return 1;
			}
			if (!S_ISDIR(st.st_mode)) {
				free(buf);
				errno = S_ISLNK(st.st_mode) ? ELOOP : ENOTDIR;
				return 1;
			}
		}
		*d_ptr++ = *s_ptr++;
	}
	free(buf);
	struct stat st = {0};
	if (lstat(path, &st)) {
		if (may_make_dir) {
			if (errno == ENOENT) {
				return 0;
			}
		}
		return 1;
	}
	if (S_ISLNK(st.st_mode)) {
		errno = ELOOP;
		return 1;
	}
	if (S_ISFIFO(st.st_mode)) {
		return 0;
	}
	if (S_ISCHR(st.st_mode)) {
		return 0;
	}
	if (S_ISBLK(st.st_mode)) {
		return 0;
	}
	if (S_ISDIR(st.st_mode)) {
		return 0;
	}
	if (S_ISREG(st.st_mode)) {
		return 0;
	}
	if (S_ISSOCK(st.st_mode)) {
		return 0;
	}
	errno = ELOOP;
	return 1;
}
static int process_cmd(struct mount_seq *s) {
	char *mnt_source = NULL;
	if (!s->target) {
		fprintf(stderr, "No target specified\n");
		return 2;
	}
	switch (s->cmd) {
		case MOUNT_SEQ_CMD_MOUNT:
			mnt_source = s->opts.mount_opts.source;
			if (mnt_source) {
				if (!s->opts.mount_opts.skip_source_symlink_check) {
					if (check_path_for_symlinks(mnt_source, 0)) {
						fprintf(stderr, "Checking %s for symlinks: %s\n", mnt_source, strerror(errno));
						return 2;
					}
				}
			} else {
				mnt_source = "/dev/null";
			}
			if (!s->skip_target_symlink_check) {
				if (check_path_for_symlinks(s->target, s->opts.mount_opts.mkdir_if_not_exist || s->opts.mount_opts.make_file_if_not_exist)) {
					fprintf(stderr, "Checking %s for symlinks: %s\n", s->target, strerror(errno));
					return 2;
				}
			}
			if (s->opts.mount_opts.mkdir_if_not_exist) {
				if (mkdir(s->target, 0700)) {
					if (errno != EEXIST) {
						fprintf(stderr, "mkdir %s: %s\n", s->target, strerror(errno));
						return 1;
					}
				}
			} else if (s->opts.mount_opts.make_file_if_not_exist) {
				if (mknod(s->target, S_IFSOCK|0600, 0)) {
					if (errno != EEXIST) {
						fprintf(stderr, "mknod %s: %s\n", s->target, strerror(errno));
						return 1;
					}
				}
			}
			if (mount(mnt_source, s->target, s->opts.mount_opts.fstype, s->opts.mount_opts.flags, s->opts.mount_opts.data)) {
				fprintf(stderr, "Mounting %s on %s failed: %s\n", mnt_source, s->target, strerror(errno));
				return 1;
			}
			break;
		case MOUNT_SEQ_CMD_MKDIR:
			if (!s->skip_target_symlink_check) {
				if (check_path_for_symlinks(s->target, 1)) {
					fprintf(stderr, "Checking %s for symlinks: %s\n", s->target, strerror(errno));
					return 2;
				}
			}
			if (mkdir(s->target, 0700)) {
				if (s->opts.mkdir_opts.no_error_if_exists && (errno == EEXIST)) {
					break;
				}
				fprintf(stderr, "mkdir %s: %s\n", s->target, strerror(errno));
				return 1;
			}
			if (s->opts.mkdir_opts.set_mode && (chmod(s->target, s->opts.mkdir_opts.mode))) {
				fprintf(stderr, "chmod %s: %s\n", s->target, strerror(errno));
				return 1;
			}
			break;
		case MOUNT_SEQ_CMD_UMOUNT:
			if (!s->skip_target_symlink_check) {
				if (check_path_for_symlinks(s->target, 0)) {
					fprintf(stderr, "Checking %s for symlinks: %s\n", s->target, strerror(errno));
					return 2;
				}
			}
			if (umount2(s->target, s->opts.umount_opts.flags)) {
				fprintf(stderr, "umount %s: %s\n", s->target, strerror(errno));
				return 1;
			}
			break;
		case MOUNT_SEQ_CMD_SYSTEM:
			if (system(s->target)) {
				return 1;
			}
			break;
		case MOUNT_SEQ_CMD_CHDIR:
			if (!s->skip_target_symlink_check) {
				if (check_path_for_symlinks(s->target, 0)) {
					fprintf(stderr, "Checking %s for symlinks: %s\n", s->target, strerror(errno));
					return 2;
				}
			}
			if (chdir(s->target)) {
				fprintf(stderr, "cd %s: %s\n", s->target, strerror(errno));
				return 1;
			}
			break;
		case MOUNT_SEQ_CMD_SYMLINK:
			if (!s->opts.symlink_opts.link_name) {
				fprintf(stderr, "No link target specified for %s\n", s->target);
				return 2;
			}
			if (!s->skip_target_symlink_check) {
				if (check_path_for_symlinks(s->target, 1)) {
					fprintf(stderr, "Checking %s for symlinks: %s\n", s->target, strerror(errno));
					return 2;
				}
			}
			if (symlink(s->opts.symlink_opts.link_name, s->target)) {
				fprintf(stderr, "symlink %s to %s: %s\n", s->target, s->opts.symlink_opts.link_name, strerror(errno));
				return 1;
			}
			break;
	}
	return 0;
}
int ctr_scripts_mount_seq_main(int argc, char **argv) {
	struct mount_seq *current = NULL;
	struct mount_seq *m_list = NULL;
	size_t m_list_size = 0;
	size_t m_list_max = 0;
	int opt = 0;
	const char *error_str = NULL;
	char i_opt = 0;
	while ((opt = getopt(argc, argv, "m:D:u:S:c:l:kKeyEM:s:t:O:F:o:f")) > 0) {
		switch(opt) {
			case 'm':
			case 'D':
			case 'u':
			case 'S':
			case 'c':
			case 'l':
				if (m_list_size >= m_list_max) {
					m_list_max += 25;
					m_list = reallocarray(m_list, m_list_max, sizeof(struct mount_seq));
					if (!m_list) {
						return 255;
					}
				}
				current = &m_list[m_list_size++];
				memset(current, 0, sizeof(struct mount_seq));
				current->target = ctrtool_strdup(optarg);
				current->cmd = opt;
				break;
			case 'k':
				if (!current) {
					goto fail_no_global;
				}
				current->skip_target_symlink_check = 1;
				break;
			case 'e':
				if (!current) {
					goto fail_no_global;
				}
				current->keep_going_if_fail = 1;
				break;
			case 'y':
				if (!current) {
					goto fail_no_global;
				}
				current->sync_after_operation = 1;
				break;
			case 'M':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'D':
						current->opts.mkdir_opts.mode = strtoull(optarg, NULL, 8);
						current->opts.mkdir_opts.set_mode = 1;
						break;
					default:
						error_str = "-M may only be used with -D";
						goto fail_all;
				}
				break;
			case 's':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						free(current->opts.mount_opts.source);
						current->opts.mount_opts.source = ctrtool_strdup(optarg);
						break;
					case 'l':
						free(current->opts.symlink_opts.link_name);
						current->opts.symlink_opts.link_name = ctrtool_strdup(optarg);
						break;
					default:
						error_str = "-s may only be used with -m or -l";
						goto fail_all;
				}
				break;
			case 't':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						free(current->opts.mount_opts.fstype);
						current->opts.mount_opts.fstype = ctrtool_strdup(optarg);
						break;
					default:
						error_str = "-t may only be used with -m";
						goto fail_all;
				}
				break;
			case 'K':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						current->opts.mount_opts.skip_source_symlink_check = 1;
						break;
					default:
						error_str = "-K may only be used with -m";
						goto fail_all;
				}
				break;
			case 'E':
			case 'f':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						if (opt == 'E') {
							current->opts.mount_opts.mkdir_if_not_exist = 1;
						} else {
							current->opts.mount_opts.make_file_if_not_exist = 1;
						}
						break;
					default:
						error_str = "-E and -f may only be used with -m";
						goto fail_all;
				}
				break;
			case 'O':
			case 'F':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						current->opts.mount_opts.flags |= search_opts(optarg, flags_bitmap_mount, &i_opt, opt == 'F');
						break;
					case 'D':
						current->opts.mkdir_opts.flags |= search_opts(optarg, flags_bitmap_mkdir, &i_opt, opt == 'F');
						current->opts.mkdir_opts.no_error_if_exists = !!(current->opts.mkdir_opts.flags & 1);
						break;
					case 'u':
						current->opts.umount_opts.flags |= search_opts(optarg, flags_bitmap_umount, &i_opt, opt == 'F');
						break;
					default:
						error_str = "-O may only be used with -m, -D, or -u";
						goto fail_all;
				}
				if (i_opt) {
					fprintf(stderr, "%s: Invalid option '%c' for -%c\n", argv[0], i_opt, current->cmd);
					return 1;
				}
				break;
			case 'o':
				if (!current) {
					goto fail_no_global;
				}
				switch (current->cmd) {
					case 'm':
						free(current->opts.mount_opts.data);
						current->opts.mount_opts.data = ctrtool_strdup(optarg);
						break;
					default:
						error_str = "-o may only be used with -m";
						goto fail_all;
				}
				break;
			default:
				/* FIXME: help text */
				return 1;
				break;
		}
	}
	int has_error = 0;
	for (size_t s = 0; s < m_list_size; s++) {
		switch(process_cmd(&m_list[s])) {
			case 1:
				if (m_list[s].keep_going_if_fail) {
					has_error = 1;
					break;
				}
			case 2:
				return 3;
				break;
		}
		if (m_list[s].sync_after_operation) {
			sync();
		}
	}
	return has_error ? 2 : 0;
fail_no_global:
	fprintf(stderr, "%s: Option may only be used after -m, -D, -u, -S, or -c\n", argv[0]);
	return 1;
fail_all:
	fprintf(stderr, "%s: %s\n", argv[0], error_str);
	return 1;
}
