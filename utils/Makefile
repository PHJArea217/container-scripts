CC ?= gcc
CCLD ?= $(CC)
AR ?= ar
CFLAGS ?= -O3 -g -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 -fPIC -fPIE
CCLDFLAGS ?= -Wl,-z,relro -Wl,-z,now -pie
CCLDFLAGS_S ?= -Wl,-z,relro -Wl,-z,now -static-pie

all: ctrtool ctrtool-static

ctrtool-static: ctrtool.a
	$(CCLD) $(CCLDFLAGS_S) -o $@ $^

ctrtool: ctrtool.a
	$(CCLD) $(CCLDFLAGS) -o $@ $^

ctrtool.a: container-launcher.o cl-nsenter.o ctrtool-common.o container-rootfs-mount.o debug_shell.o mini-init.o reset_cgroup.o set_fds.o simple-renameat2.o mount_seq.o main.o
	$(AR) r $@ $^

%.o: %.c ctrtool-common.h
	$(CC) $(CFLAGS) -c -o $@ $< -Wall

clean:
	rm -f *.o ctrtool ctrtool-static ctrtool.a

.PHONY: all clean
